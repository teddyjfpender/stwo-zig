/-
**The proof wires** (`proof.zig` `Proof(Var)`, guessed by the circuit).

`mapG` is the generic list emitter; `ProofRegs` is the register record of the
guessed proof, shaped by the static profile (`nq` queries, evaluation
domain log `L`); `guessG` allocates it — QM31 values as `.guess`, M31
eval-domain samples as `.guessM31`, hash words as `guess_u32`
(`guessHashG`). `GuessFacts` is what the gates give: every hash is a
u32 word list (read back by `regWords`), every sample is in the base
field.
-/
import StwoVerifier.GuessGadgets
import StwoVerifier.PhaseTranscript
import StwoVerifier.CircuitAir

namespace StwoVerifier.Gadgets

open StwoVerifier StwoVerifier.Gates

/-! ### A generic list emitter -/

noncomputable def mapG {α β : Type} (f : β → ℕ → Out α) : List β → ℕ → Out (List α)
  | [], n => ⟨[], [], n⟩
  | b :: bs, n => (f b n).seq fun a n => (mapG f bs n).seq fun as n => ⟨[], a :: as, n⟩

theorem mapG_length {α β : Type} (f : β → ℕ → Out α) :
    ∀ (bs : List β) (n : ℕ), (mapG f bs n).res.length = bs.length
  | [], _ => rfl
  | b :: bs, n => by
    unfold mapG
    rw [seq_res, seq_res]
    simp [mapG_length f bs]

theorem mapG_sound {ρ : ℕ → QM31} {α β : Type} {f : β → ℕ → Out α} (P : β → α → Prop)
    (hf : ∀ b n, AllHold ρ (f b n).ops → P b (f b n).res) :
    ∀ (bs : List β) (n : ℕ), AllHold ρ (mapG f bs n).ops → List.Forall₂ P bs (mapG f bs n).res
  | [], _, _ => List.Forall₂.nil
  | b :: bs, n, h => by
    unfold mapG at h ⊢
    rw [allHold_seq] at h
    obtain ⟨h1, h⟩ := h
    rw [allHold_seq] at h
    obtain ⟨h2, -⟩ := h
    rw [seq_res, seq_res]
    exact List.Forall₂.cons (hf b n h1) (mapG_sound P hf bs _ h2)

theorem forall2_range_getD {α : Type} {P : ℕ → α → Prop} {m : ℕ} {l : List α} (d : α)
    (h : List.Forall₂ P (List.range m) l) : ∀ i, i < m → P i (l.getD i d) := by
  intro i hi
  have hl := h.length_eq
  rw [List.length_range] at hl
  have := (List.forall₂_iff_get.mp h).2 i (by simpa using hi) (by omega)
  simp only [List.get_eq_getElem, List.getElem_range] at this
  rw [List.getD_eq_getElem?_getD, List.getElem?_eq_getElem (by omega)]
  exact this

/-! ### Guess gadgets -/

/-- An unconstrained QM31 guess. -/
def gQ (n : ℕ) : Out ℕ := ⟨[.guess n], n, n + 1⟩

/-- An M31 guess. -/
def gM (n : ℕ) : Out ℕ := ⟨[.guessM31 n], n, n + 1⟩

theorem gM_sound {ρ : ℕ → QM31} {n : ℕ} (h : AllHold ρ (gM n).ops) : IsBase (ρ (gM n).res) :=
  h _ List.mem_cons_self

/-- The words a list of u32 registers carries. -/
noncomputable def regWords (ρ : ℕ → QM31) (regs : List ℕ) : List Blake2s.Word :=
  regs.map fun r => wordOf (ρ r)

/-- A guessed hash: eight u32 registers. -/
def HashRegs (ρ : ℕ → QM31) (regs : List ℕ) : Prop :=
  RegsWords ρ regs (regWords ρ regs) ∧ regs.length = 8

theorem regsWords_eq {ρ : ℕ → QM31} {regs : List ℕ} {ws : List Blake2s.Word}
    (h : RegsWords ρ regs ws) : ws = regWords ρ regs := by
  refine List.ext_getElem (by rw [← h.len]; simp [regWords]) fun j h1 h2 => ?_
  have hj : j < regs.length := by rw [h.len]; exact h1
  have := h.val j hj
  rw [List.getD_eq_getElem?_getD, List.getElem?_eq_getElem hj, List.getD_eq_getElem?_getD,
    List.getElem?_eq_getElem h1] at this
  simp only [Option.getD_some] at this
  simp only [regWords, List.getElem_map]
  rw [this, wordOf_packW]

theorem guessHashG_regs {ρ : ℕ → QM31} {n : ℕ} (h : AllHold ρ (guessHashG n).ops) :
    HashRegs ρ (guessHashG n).res := by
  obtain ⟨hr, hl⟩ := guessHashG_sound h
  have := regsWords_eq hr
  refine ⟨this ▸ hr, ?_⟩
  rw [hr.len, hl]

/-! ### The proof record -/

/-- The guessed proof's registers. -/
structure ProofRegs where
  salt : ℕ
  traceRoot : List ℕ
  interNonce : ℕ
  claimed : List ℕ
  interRoot : List ℕ
  compRoot : List ℕ
  ppAt : List ℕ
  traceAt : List ℕ
  comps : List (List ℕ × List (ℕ × ℕ))
  compAt : List ℕ
  friRoots : List (List ℕ)
  lastCoef : ℕ
  powNonce : ℕ
  /-- tree → column → query. -/
  cols : List (List (List ℕ))
  /-- tree → query → level → hash. -/
  authT : List (List (List (List ℕ)))
  /-- layer → query → (w0, w1). -/
  friWit : List (List (ℕ × ℕ))
  /-- layer → query → level → hash. -/
  friAuth : List (List (List (List ℕ)))

/-- Column counts of the four trees. -/
def treeCols : List ℕ := [CircuitAirData.nPp, CircuitAirData.nTrace, CircuitAirData.nInter, 8]

/-- The interaction samples of one component of `n` columns: `n − 4`
plain, four cumulative `(at_prev, at_oods)`. -/
noncomputable def guessComp (n : ℕ) (k : ℕ) : Out (List ℕ × List (ℕ × ℕ)) :=
  (mapG (fun _ => gQ) (List.range (n - 4)) k).seq fun plain k =>
  (mapG (fun _ k => (gQ k).seq fun a k => (gQ k).seq fun b k => ⟨[], (a, b), k⟩)
    (List.range 4) k).seq fun cum k => ⟨[], (plain, cum), k⟩

/-- **The guess phase**. -/
noncomputable def guessG (nq L : ℕ) (n : ℕ) : Out ProofRegs :=
  (gQ n).seq fun salt n =>
  (guessHashG n).seq fun traceRoot n =>
  (gQ n).seq fun interNonce n =>
  (mapG (fun _ => gQ) (List.range 11) n).seq fun claimed n =>
  (guessHashG n).seq fun interRoot n =>
  (guessHashG n).seq fun compRoot n =>
  (mapG (fun _ => gQ) (List.range CircuitAirData.nPp) n).seq fun ppAt n =>
  (mapG (fun _ => gQ) (List.range CircuitAirData.nTrace) n).seq fun traceAt n =>
  (mapG guessComp CircuitAirData.interShape.toList n).seq fun comps n =>
  (mapG (fun _ => gQ) (List.range 8) n).seq fun compAt n =>
  (mapG (fun _ => guessHashG) (List.range (L - 1)) n).seq fun friRoots n =>
  (gQ n).seq fun lastCoef n =>
  (gQ n).seq fun powNonce n =>
  (mapG (fun nc => mapG (fun _ => mapG (fun _ => gM) (List.range nq)) (List.range nc))
    treeCols n).seq fun cols n =>
  (mapG (fun _ => mapG (fun _ => mapG (fun _ => guessHashG) (List.range L)) (List.range nq))
    (List.range 4) n).seq fun authT n =>
  (mapG (fun _ => mapG (fun _ k => (gQ k).seq fun a k => (gQ k).seq fun b k => ⟨[], (a, b), k⟩)
    (List.range nq)) (List.range (L - 1)) n).seq fun friWit n =>
  (mapG (fun l => mapG (fun _ => mapG (fun _ => guessHashG) (List.range (L - 1 - l)))
    (List.range nq)) (List.range (L - 1)) n).seq fun friAuth n =>
  ⟨[], ⟨salt, traceRoot, interNonce, claimed, interRoot, compRoot, ppAt, traceAt, comps, compAt,
    friRoots, lastCoef, powNonce, cols, authT, friWit, friAuth⟩, n⟩

/-- What the guess gates give. -/
structure GuessFacts (ρ : ℕ → QM31) (nq L : ℕ) (g : ProofRegs) : Prop where
  traceRoot : HashRegs ρ g.traceRoot
  interRoot : HashRegs ρ g.interRoot
  compRoot : HashRegs ρ g.compRoot
  claimedLen : g.claimed.length = 11
  ppLen : g.ppAt.length = CircuitAirData.nPp
  traceLen : g.traceAt.length = CircuitAirData.nTrace
  compLen : g.compAt.length = 8
  compsLen : g.comps.length = 11
  compsShape : ∀ j, j < 11 →
    (g.comps.getD j ([], [])).1.length = CircuitAirData.interShape.toList.getD j 0 - 4 ∧
    (g.comps.getD j ([], [])).2.length = 4
  friRootsLen : g.friRoots.length = L - 1
  friRoots : ∀ l, l < L - 1 → HashRegs ρ (g.friRoots.getD l [])
  cols : ∀ t, t < 4 → ∀ c, c < treeCols.getD t 0 → ∀ q, q < nq →
    IsBase (ρ (((g.cols.getD t []).getD c []).getD q 0))
  colsLen : ∀ t, t < 4 → (g.cols.getD t []).length = treeCols.getD t 0 ∧
    ∀ c, c < treeCols.getD t 0 → ((g.cols.getD t []).getD c []).length = nq
  authLen : ∀ t, t < 4 → ∀ q, q < nq → ((g.authT.getD t []).getD q []).length = L
  auth : ∀ t, t < 4 → ∀ q, q < nq → ∀ k, k < L →
    HashRegs ρ (((g.authT.getD t []).getD q []).getD k [])
  friAuthLen : ∀ l, l < L - 1 → ∀ q, q < nq → ((g.friAuth.getD l []).getD q []).length = L - 1 - l
  friAuth : ∀ l, l < L - 1 → ∀ q, q < nq → ∀ k, k < L - 1 - l →
    HashRegs ρ (((g.friAuth.getD l []).getD q []).getD k [])

theorem mapG_gQ_length {m n : ℕ} : (mapG (fun _ => gQ) (List.range m) n).res.length = m := by
  rw [mapG_length]; simp

set_option maxHeartbeats 16000000 in
theorem guessG_sound {ρ : ℕ → QM31} {nq L n : ℕ} (h : AllHold ρ (guessG nq L n).ops) :
    GuessFacts ρ nq L (guessG nq L n).res := by
  unfold guessG at h ⊢
  set SA := gQ n with hSAdef
  rw [allHold_seq] at h
  rw [seq_res]
  obtain ⟨hSA, h⟩ := h
  beta_reduce at h ⊢
  set TR := guessHashG SA.next with hTRdef
  rw [allHold_seq] at h
  rw [seq_res]
  obtain ⟨hTR, h⟩ := h
  beta_reduce at h ⊢
  set IN := gQ TR.next with hINdef
  rw [allHold_seq] at h
  rw [seq_res]
  obtain ⟨hIN, h⟩ := h
  beta_reduce at h ⊢
  set CL := mapG (fun _ => gQ) (List.range 11) IN.next with hCLdef
  rw [allHold_seq] at h
  rw [seq_res]
  obtain ⟨hCL, h⟩ := h
  beta_reduce at h ⊢
  set IR := guessHashG CL.next with hIRdef
  rw [allHold_seq] at h
  rw [seq_res]
  obtain ⟨hIR, h⟩ := h
  beta_reduce at h ⊢
  set CR := guessHashG IR.next with hCRdef
  rw [allHold_seq] at h
  rw [seq_res]
  obtain ⟨hCR, h⟩ := h
  beta_reduce at h ⊢
  set PA := mapG (fun _ => gQ) (List.range CircuitAirData.nPp) CR.next with hPAdef
  rw [allHold_seq] at h
  rw [seq_res]
  obtain ⟨hPA, h⟩ := h
  beta_reduce at h ⊢
  set TA := mapG (fun _ => gQ) (List.range CircuitAirData.nTrace) PA.next with hTAdef
  rw [allHold_seq] at h
  rw [seq_res]
  obtain ⟨hTA, h⟩ := h
  beta_reduce at h ⊢
  set CM := mapG guessComp CircuitAirData.interShape.toList TA.next with hCMdef
  rw [allHold_seq] at h
  rw [seq_res]
  obtain ⟨hCM, h⟩ := h
  beta_reduce at h ⊢
  set CA := mapG (fun _ => gQ) (List.range 8) CM.next with hCAdef
  rw [allHold_seq] at h
  rw [seq_res]
  obtain ⟨hCA, h⟩ := h
  beta_reduce at h ⊢
  set FR := mapG (fun _ => guessHashG) (List.range (L - 1)) CA.next with hFRdef
  rw [allHold_seq] at h
  rw [seq_res]
  obtain ⟨hFR, h⟩ := h
  beta_reduce at h ⊢
  set LC := gQ FR.next with hLCdef
  rw [allHold_seq] at h
  rw [seq_res]
  obtain ⟨hLC, h⟩ := h
  beta_reduce at h ⊢
  set PN := gQ LC.next with hPNdef
  rw [allHold_seq] at h
  rw [seq_res]
  obtain ⟨hPN, h⟩ := h
  beta_reduce at h ⊢
  set CO := mapG (fun nc => mapG (fun _ => mapG (fun _ => gM) (List.range nq)) (List.range nc)) treeCols PN.next with hCOdef
  rw [allHold_seq] at h
  rw [seq_res]
  obtain ⟨hCO, h⟩ := h
  beta_reduce at h ⊢
  set AT := mapG (fun _ => mapG (fun _ => mapG (fun _ => guessHashG) (List.range L)) (List.range nq)) (List.range 4) CO.next with hATdef
  rw [allHold_seq] at h
  rw [seq_res]
  obtain ⟨hAT, h⟩ := h
  beta_reduce at h ⊢
  set FW := mapG (fun _ => mapG (fun _ k => (gQ k).seq fun a k => (gQ k).seq fun b k => ⟨[], (a, b), k⟩) (List.range nq)) (List.range (L - 1)) AT.next with hFWdef
  rw [allHold_seq] at h
  rw [seq_res]
  obtain ⟨hFW, h⟩ := h
  beta_reduce at h ⊢
  set FA := mapG (fun l => mapG (fun _ => mapG (fun _ => guessHashG) (List.range (L - 1 - l))) (List.range nq)) (List.range (L - 1)) FW.next with hFAdef
  rw [allHold_seq] at h
  rw [seq_res]
  obtain ⟨hFA, h⟩ := h
  beta_reduce at h ⊢
  -- Shapes from the emitters.
  have hcm : List.Forall₂ (fun n (c : List ℕ × List (ℕ × ℕ)) => c.1.length = n - 4 ∧ c.2.length = 4)
      CircuitAirData.interShape.toList CM.res := by
    refine mapG_sound _ (fun b k _ => ?_) _ _ hCM
    unfold guessComp
    rw [seq_res, seq_res]
    exact ⟨by rw [mapG_length]; simp, by rw [mapG_length]; simp⟩
  have hfr := mapG_sound (fun _ r => HashRegs ρ r) (fun _ k hk => guessHashG_regs hk) _ _ hFR
  have hco := mapG_sound (fun nc (cs : List (List ℕ)) => cs.length = nc ∧
      List.Forall₂ (fun _ (col : List ℕ) => col.length = nq ∧
        List.Forall₂ (fun _ r => IsBase (ρ r)) (List.range nq) col) (List.range nc) cs)
    (fun nc k hk => ⟨by rw [mapG_length]; simp,
      mapG_sound _ (fun _ k' hk' => ⟨by rw [mapG_length]; simp,
        mapG_sound _ (fun _ k'' hk'' => gM_sound hk'') _ _ hk'⟩) _ _ hk⟩) _ _ hCO
  have hat := mapG_sound (fun _ (qs : List (List (List ℕ))) =>
      List.Forall₂ (fun _ (ks : List (List ℕ)) => ks.length = L ∧
        List.Forall₂ (fun _ r => HashRegs ρ r) (List.range L) ks) (List.range nq) qs)
    (fun _ k hk => mapG_sound _ (fun _ k' hk' => ⟨by rw [mapG_length]; simp,
      mapG_sound _ (fun _ k'' hk'' => guessHashG_regs hk'') _ _ hk'⟩) _ _ hk) _ _ hAT
  have hfa := mapG_sound (fun l (qs : List (List (List ℕ))) =>
      List.Forall₂ (fun _ (ks : List (List ℕ)) => ks.length = L - 1 - l ∧
        List.Forall₂ (fun _ r => HashRegs ρ r) (List.range (L - 1 - l)) ks) (List.range nq) qs)
    (fun l k hk => mapG_sound _ (fun _ k' hk' => ⟨by rw [mapG_length]; simp,
      mapG_sound _ (fun _ k'' hk'' => guessHashG_regs hk'') _ _ hk'⟩) _ _ hk) _ _ hFA
  refine ⟨guessHashG_regs hTR, guessHashG_regs hIR, guessHashG_regs hCR,
    by simp only [hCLdef, mapG_length, List.length_range],
    by simp only [hPAdef, mapG_length, List.length_range],
    by simp only [hTAdef, mapG_length, List.length_range],
    by simp only [hCAdef, mapG_length, List.length_range], ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · rw [← hcm.length_eq]; simp [CircuitAirData.interShape]
  · intro j hj
    have hj' : j < CircuitAirData.interShape.toList.length := by
      simp [CircuitAirData.interShape]; exact hj
    have := (List.forall₂_iff_get.mp hcm).2 j hj' (by rw [← hcm.length_eq]; exact hj')
    simp only [List.get_eq_getElem] at this
    have e1 := List.getD_eq_getElem CM.res ([], []) (by rw [← hcm.length_eq]; exact hj')
    have e2 := List.getD_eq_getElem CircuitAirData.interShape.toList 0 hj'
    rw [e1, e2]
    exact this
  · rw [mapG_length]; simp
  · intro l hl
    exact forall2_range_getD [] hfr l hl
  · intro t ht c hc q hq
    have hco' : List.Forall₂ _ treeCols CO.res := hco
    have htl : t < treeCols.length := by simp [treeCols]; omega
    obtain ⟨-, h2⟩ := (List.forall₂_iff_get.mp hco').2 t htl (by rw [← hco'.length_eq]; exact htl)
    simp only [List.get_eq_getElem] at h2
    have hc' : c < treeCols[t] := by
      rw [← List.getD_eq_getElem treeCols 0 htl]; exact hc
    obtain ⟨-, h3⟩ := forall2_range_getD [] h2 c hc'
    have := forall2_range_getD 0 h3 q hq
    rw [List.getD_eq_getElem?_getD (l := CO.res),
      List.getElem?_eq_getElem (by rw [← hco'.length_eq]; exact htl)]
    exact this
  · intro t ht
    have hco' : List.Forall₂ _ treeCols CO.res := hco
    have htl : t < treeCols.length := by simp [treeCols]; omega
    obtain ⟨h1, h2⟩ := (List.forall₂_iff_get.mp hco').2 t htl (by rw [← hco'.length_eq]; exact htl)
    simp only [List.get_eq_getElem] at h1 h2
    rw [List.getD_eq_getElem?_getD (l := CO.res),
      List.getElem?_eq_getElem (by rw [← hco'.length_eq]; exact htl)]
    simp only [Option.getD_some]
    refine ⟨by rw [h1, List.getD_eq_getElem _ 0 htl], fun c hc => ?_⟩
    have hc' : c < treeCols[t] := by
      rw [← List.getD_eq_getElem treeCols 0 htl]; exact hc
    exact (forall2_range_getD [] h2 c hc').1
  · intro t ht q hq
    exact (forall2_range_getD [] (forall2_range_getD [] hat t ht) q hq).1
  · intro t ht q hq k hk
    exact forall2_range_getD [] (forall2_range_getD [] (forall2_range_getD [] hat t ht) q hq).2 k hk
  · intro l hl q hq
    exact (forall2_range_getD [] (forall2_range_getD [] hfa l hl) q hq).1
  · intro l hl q hq k hk
    exact forall2_range_getD [] (forall2_range_getD [] (forall2_range_getD [] hfa l hl) q hq).2 k hk

end StwoVerifier.Gadgets
