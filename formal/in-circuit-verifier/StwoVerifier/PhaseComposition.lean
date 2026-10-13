/-
**Phase 2 of the in-circuit `verify`: relation uses, OODS mix and the
composition check** (`verify.zig` from `check_relation_uses` through
`ctx.eq(composition_eval, expected_composition_eval)`).

`phase2G` emits the relation-use bound, unpacks the component sizes and
the DAG's n-instance bits, mixes the OODS samples, evaluates the
recorded composition DAG with the vanishing division, reconstructs the
proof's composition value and equates the two. `phase2G_sound` gives the
spec's `relationUsesOk`, the post-mix channel digest, and — for any
sampled-value list laid out as the proof wires are — the spec's
`extractCompositionOodsEval` and `circuitAir.evalComposition` agreeing on
one value.
-/
import StwoVerifier.PhaseTranscript
import StwoVerifier.RelationUses
import StwoVerifier.DagGadget
import StwoVerifier.OodsGadgets
import StwoVerifier.CircuitAir

namespace StwoVerifier.Gadgets

open StwoVerifier StwoVerifier.Gates CircuitAirData

/-- The DAG's n-instance-bit atoms: `get_n_instances_bit` per
`(component, bit)`. -/
noncomputable def nbitsG (bits : List SimdReg) : List (ℕ × ℕ) → ℕ → Out (List ℕ)
  | [], n => ⟨[], [], n⟩
  | (c, b) :: rest, n =>
    let u := unpackIdx ((bits.getD b dummySimd).data.getD (c / 4) 0) (c % 4) n
    let r := nbitsG bits rest u.next
    ⟨u.ops ++ r.ops, u.res :: r.res, r.next⟩

theorem nbitsG_sound {ρ : ℕ → QM31} {bits : List SimdReg} :
    ∀ (atoms : List (ℕ × ℕ)) (n : ℕ), AllHold ρ (nbitsG bits atoms n).ops →
      (nbitsG bits atoms n).res.length = atoms.length ∧
      ∀ k, k < atoms.length → ρ ((nbitsG bits atoms n).res.getD k 0)
        = QM31.fromBase (SimdReg.lane ρ (bits.getD (atoms.getD k (0, 0)).2 dummySimd)
            (atoms.getD k (0, 0)).1)
  | [], _, _ => ⟨rfl, fun k hk => absurd hk (by simp)⟩
  | (c, b) :: rest, n, h => by
    rw [show (nbitsG bits ((c, b) :: rest) n).ops =
      (unpackIdx ((bits.getD b dummySimd).data.getD (c / 4) 0) (c % 4) n).ops ++
        (nbitsG bits rest (unpackIdx ((bits.getD b dummySimd).data.getD (c / 4) 0)
          (c % 4) n).next).ops from rfl, allHold_append] at h
    obtain ⟨h1, h2⟩ := h
    obtain ⟨ihl, ihv⟩ := nbitsG_sound rest _ h2
    refine ⟨by show _ + 1 = _; rw [ihl]; rfl, fun k hk => ?_⟩
    rcases k with _ | k
    · show ρ (unpackIdx _ _ n).res = _
      rw [unpackIdx_sound (Nat.mod_lt _ (by norm_num)) h1]
      rfl
    · show ρ ((nbitsG bits rest _).res.getD k 0) = _
      rw [ihv k (by simp at hk; omega)]
      rfl

/-- The OODS samples in mix order (`mixOodsValues`). -/
def oodsVals (ppAt traceAt : List ℕ) (interAt : List (ℕ × Option ℕ)) (compAt : List ℕ) :
    List ℕ :=
  ppAt ++ traceAt ++ interAt.flatMap (fun c => c.2.toList ++ [c.1]) ++ compAt

/-- The DAG input registers, in `CircuitAirData`'s flat layout. -/
def dagInRegs (oodsX : ℕ) (ppPos ppAt traceAt : List ℕ) (interAt : List (ℕ × Option ℕ))
    (coeff z alpha : ℕ) (claimed sizeRegs nbitRegs : List ℕ) : Array ℕ :=
  #[oodsX] ++ (ppPos.map fun j => ppAt.getD j 0).toArray ++ traceAt.toArray
    ++ (interAt.map (·.1)).toArray ++ (interAt.filterMap (·.2)).toArray
    ++ #[coeff, z, alpha] ++ claimed.toArray ++ sizeRegs.toArray ++ nbitRegs.toArray

/-- **Phase 2**. Returns the post-mix digest registers. -/
noncomputable def phase2G (zero one : ℕ) (logTrace : ℕ) (low high : ℕ)
    (sizeBits : List SimdReg) (sizes : SimdReg) (oods : PointReg) (coeff z alpha : ℕ)
    (ppPos ppAt traceAt : List ℕ) (interAt : List (ℕ × Option ℕ)) (compAt claimed : List ℕ)
    (n : ℕ) : Out (ℕ × ℕ) :=
  (checkRelUsesG zero sizeBits 3 11 n).seq fun _ n =>
  (unpackFrom sizes 11 0 n).seq fun us n =>
  (nbitsG sizeBits nbitAtoms.toList n).seq fun nb n =>
  (mixQm31sG low high (oodsVals ppAt traceAt interAt compAt) n).seq fun mo n =>
  (compositionG zero one (dagInRegs oods.x ppPos ppAt traceAt interAt coeff z alpha claimed us nb)
    oods.x logTrace n).seq fun cp n =>
  (extractExpectedCompositionEvalG one (fun i => compAt.getD i 0) oods.x (logTrace + 1) n).seq
    fun ex n =>
  ⟨[.eq cp ex], mo, n⟩

/-! ### The sampled values the proof wires carry -/

/-- The proof's sampled values (tree → column → samples) from the OODS
sample registers: cumulative sums `[at_prev, at_oods]`. -/
def svOf (ρ : ℕ → QM31) (ppAt traceAt : List ℕ) (interAt : List (ℕ × Option ℕ))
    (compAt : List ℕ) : List (List (List QM31)) :=
  [ppAt.map (fun r => [ρ r]), traceAt.map (fun r => [ρ r]),
   interAt.map (fun c => c.2.toList.map ρ ++ [ρ c.1]), compAt.map (fun r => [ρ r])]

theorem flatten_map_single {α β : Type} (f : α → β) :
    ∀ l : List α, (l.map fun r => [f r]).flatten = l.map f
  | [] => rfl
  | a :: l => by simp [flatten_map_single f l]

theorem flatten_map_eq_flatMap {α β : Type} (g : α → List β) :
    ∀ l : List α, (l.map g).flatten = l.flatMap g
  | [] => rfl
  | a :: l => by simp [flatten_map_eq_flatMap g l]

theorem svOf_flatten (ρ : ℕ → QM31) (ppAt traceAt : List ℕ) (interAt : List (ℕ × Option ℕ))
    (compAt : List ℕ) :
    ((svOf ρ ppAt traceAt interAt compAt).map (·.flatten)).flatten
      = (oodsVals ppAt traceAt interAt compAt).map ρ := by
  unfold svOf oodsVals
  simp only [List.map_cons, List.map_nil, List.flatten_cons, List.flatten_nil, List.append_nil,
    List.map_append, List.map_flatMap]
  rw [flatten_map_single, flatten_map_single, flatten_map_single, flatten_map_eq_flatMap]
  simp only [List.append_assoc]

theorem mapM_single {α : Type} (f : α → QM31) :
    ∀ l : List α, (l.map fun v => [f v]).mapM CircuitAir.single = .ok (l.map f)
  | [] => rfl
  | v :: rest => by
    rw [List.map_cons, List.mapM_cons, mapM_single f rest]
    rfl

theorem interSample_mapM (ρ : ℕ → QM31) :
    ∀ (interAt : List (ℕ × Option ℕ)) (kinds : List Bool),
      interAt.map (fun c => c.2.isSome) = kinds →
      ((interAt.map fun c => c.2.toList.map ρ ++ [ρ c.1]).zip kinds).mapM CircuitAir.interSample
        = .ok (interAt.map fun c => (ρ c.1, c.2.map ρ))
  | [], kinds, hk => by subst hk; rfl
  | c :: rest, kinds, hk => by
    subst hk
    simp only [List.map_cons, List.zip_cons_cons, List.mapM_cons]
    rw [interSample_mapM ρ rest _ rfl]
    obtain ⟨o, p⟩ := c
    cases p with
    | none => rfl
    | some p => rfl

theorem filterMap_snd_map (ρ : ℕ → QM31) :
    ∀ interAt : List (ℕ × Option ℕ),
      (interAt.map fun c => (ρ c.1, c.2.map ρ)).filterMap (·.2)
        = (interAt.filterMap (·.2)).map ρ
  | [] => rfl
  | (o, none) :: rest => by simp [filterMap_snd_map ρ rest]
  | (o, some p) :: rest => by simp [filterMap_snd_map ρ rest]

theorem mapM_single_pos (ρ : ℕ → QM31) (ppAt : List ℕ) :
    ∀ ppPos : List ℕ, (∀ j ∈ ppPos, j < ppAt.length) →
      ppPos.mapM (fun j => CircuitAir.single (((ppAt.map fun r => [ρ r])).getD j []))
        = .ok (ppPos.map fun j => ρ (ppAt.getD j 0))
  | [], _ => rfl
  | j :: rest, h => by
    rw [List.mapM_cons, mapM_single_pos ρ ppAt rest (fun k hk => h k (List.mem_cons_of_mem _ hk))]
    have hj := h j List.mem_cons_self
    simp only [List.getD_eq_getElem?_getD, List.getElem?_map, List.getElem?_eq_getElem hj,
      Option.map_some, Option.getD_some, List.map_cons]
    rfl

/-- The spec's flat DAG inputs on the proof-wire sampled values. -/
noncomputable def specInputs (ρ : ℕ → QM31) (pt : PointQ) (ppPos ppAt traceAt : List ℕ)
    (interAt : List (ℕ × Option ℕ)) (r z α : QM31) (claimedV : List QM31)
    (logSizes : List ℕ) : Array QM31 :=
  #[pt.x] ++ (ppPos.map fun j => ρ (ppAt.getD j 0)).toArray ++ (traceAt.map ρ).toArray
    ++ (interAt.map fun c => ρ c.1).toArray ++ ((interAt.filterMap (·.2)).map ρ).toArray
    ++ #[r, z, α] ++ claimedV.toArray
    ++ (logSizes.map fun l => QM31.fromBase ((2 ^ l : Nat) : F)).toArray
    ++ (nbitAtoms.toList.map fun cb =>
        if logSizes.getD cb.1 0 = cb.2 then QM31.one else QM31.zero).toArray

theorem flatInputs_ok (ρ : ℕ → QM31) (pt : PointQ) (ppPos ppAt traceAt : List ℕ)
    (interAt : List (ℕ × Option ℕ)) (compAt : List ℕ) (r z α : QM31) (claimedV : List QM31)
    (logSizes : List ℕ)
    (hpp : ppAt.length = nPp) (hpos : ppPos.length = nPp) (hposlt : ∀ j ∈ ppPos, j < ppAt.length)
    (htr : traceAt.length = nTrace) (hin : interAt.length = nInter)
    (hkinds : interAt.map (fun c => c.2.isSome) = CircuitAir.cumulativeKinds)
    (hcl : claimedV.length = 11) (hls : logSizes.length = 11) :
    CircuitAir.flatInputs pt (svOf ρ ppAt traceAt interAt compAt) r z α claimedV logSizes ppPos
      = .ok (specInputs ρ pt ppPos ppAt traceAt interAt r z α claimedV logSizes) := by
  unfold CircuitAir.flatInputs
  simp only [svOf, List.getD_cons_zero, List.getD_cons_succ, List.length_map]
  rw [if_neg (by rw [hpp, hpos]; simp), mapM_single_pos ρ ppAt ppPos hposlt]
  simp only [pure, Except.pure, bind, Except.bind]
  rw [mapM_single]
  simp only []
  rw [if_neg (by rw [List.length_map, htr]; simp), if_neg (by rw [hin]; simp),
    interSample_mapM ρ interAt _ hkinds]
  simp only []
  rw [if_neg (by rw [hcl, hls]; decide)]
  unfold specInputs
  rw [List.map_map, filterMap_snd_map]
  rfl

/-- The proof's composition value at the OODS point, from its eight
composition samples. -/
theorem extract_ok (ρ : ℕ → QM31) (ppAt traceAt : List ℕ) (interAt : List (ℕ × Option ℕ))
    (compAt : List ℕ) (pt : PointQ) (k : ℕ) (hlen : compAt.length = 8) (hk : 1 < k) :
    extractCompositionOodsEval (svOf ρ ppAt traceAt interAt compAt) pt k 1
      = reconstructChunks
          [fromPartialEvals [ρ (compAt.getD 0 0), ρ (compAt.getD 1 0), ρ (compAt.getD 2 0),
             ρ (compAt.getD 3 0)],
           fromPartialEvals [ρ (compAt.getD 4 0), ρ (compAt.getD 5 0), ρ (compAt.getD 6 0),
             ρ (compAt.getD 7 0)]] pt k 1 := by
  match compAt, hlen with
  | [c0, c1, c2, c3, c4, c5, c6, c7], _ =>
    unfold extractCompositionOodsEval
    rw [if_neg (by omega)]
    rfl

theorem arr_getD_map (ρ : ℕ → QM31) (zero : ℕ) (hz : ρ zero = 0) (arr : Array ℕ) (a : ℕ) :
    ρ (arr.getD a zero) = (arr.map ρ).getD a QM31.zero := by
  rw [Array.getD_eq_getD_getElem?, Array.getD_eq_getD_getElem?, Array.getElem?_map]
  cases arr[a]? <;> simp [hz]

/-- What phase 2 establishes. -/
def P2Spec (ρ : ℕ → QM31) (layout : List (String × ℕ)) (logSizes : List ℕ) (logTrace : ℕ)
    (s : Channel.St) (P : PointQ) (coeff z alpha : ℕ) (ppAt traceAt : List ℕ)
    (interAt : List (ℕ × Option ℕ)) (compAt claimed : List ℕ) (res : ℕ × ℕ) : Prop :=
  CircuitVerify.relationUsesOk logSizes = true ∧
  ChDigest ρ res.1 res.2
    (Channel.mixFelts true s ((oodsVals ppAt traceAt interAt compAt).map ρ)).digest ∧
  ∃ v, extractCompositionOodsEval (svOf ρ ppAt traceAt interAt compAt) P (logTrace + 1) 1
      = some v ∧
    (CircuitAir.circuitAir layout (ρ z) (ρ alpha) (claimed.map ρ) logSizes).evalComposition P
      (svOf ρ ppAt traceAt interAt compAt) (ρ coeff) logTrace = .ok v

theorem evalComposition_eq (layout : List (String × ℕ)) (z alpha : QM31) (cs : List QM31)
    (ls : List ℕ) (pt : PointQ) (sv : List (List (List QM31))) (r : QM31) (m : ℕ) :
    (CircuitAir.circuitAir layout z alpha cs ls).evalComposition pt sv r m
      = (CircuitAir.flatInputs pt sv r z alpha cs ls (CircuitAir.ppPositions layout)) >>=
          fun inputs => if ¬ CircuitAir.eqConditionsHold inputs = true
            then throw VError.shapeMismatch else pure (CircuitAir.composition inputs m) := rfl

set_option maxHeartbeats 16000000 in
theorem phase2G_sound {ρ : ℕ → QM31} {zero one logTrace low high : ℕ}
    {sizeBits : List SimdReg} {sizes : SimdReg} {oods : PointReg} {coeff z alpha : ℕ}
    {ppPos ppAt traceAt : List ℕ} {interAt : List (ℕ × Option ℕ)} {compAt claimed : List ℕ}
    {n : ℕ} (layout : List (String × ℕ)) (logSizes : List ℕ) (s : Channel.St)
    (hzero : ρ zero = 0) (hone : ρ one = 1)
    (hd : ChDigest ρ low high s.digest) (hdlen : s.digest.length = 32)
    (hlsl : logSizes.length = 11) (hlsP : ∀ j, j < 11 → logSizes.getD j 0 < P)
    (hlv : ∀ j, j < 11 → logSizes.getD j 0 ≤ logTrace)
    (hlT : 16 < logTrace + 1) (hlT31 : logTrace + 1 ≤ 31) (hlT18 : 18 < logTrace + 1)
    (hsbl : sizeBits.length = logTrace + 1) (hsbs : ∀ b ∈ sizeBits, BitShape b 11 3)
    (hsb : ∀ j, j < 11 → ∀ t, t < logTrace + 1 →
      SimdReg.lane ρ (sizeBits.getD t dummySimd) j
        = if t = logSizes.getD j 0 then 1 else 0)
    (hszl : sizes.len = 11) (hszd : sizes.data.length = 3)
    (hsz : ∀ j, j < 11 → SimdReg.lane ρ sizes j = 2 ^ (logSizes.getD j 0))
    (hP : OnCircleQ (oods.val ρ))
    (hpp : ppAt.length = nPp) (hpos : ppPos.length = nPp) (hposlt : ∀ j ∈ ppPos, j < ppAt.length)
    (hppPos : ppPos = CircuitAir.ppPositions layout)
    (htr : traceAt.length = nTrace) (hin : interAt.length = nInter)
    (hkinds : interAt.map (fun c => c.2.isSome) = CircuitAir.cumulativeKinds)
    (hcl : claimed.length = 11) (hcmp : compAt.length = 8)
    (h : AllHold ρ (phase2G zero one logTrace low high sizeBits sizes oods coeff z alpha
      ppPos ppAt traceAt interAt compAt claimed n).ops) :
    P2Spec ρ layout logSizes logTrace s (oods.val ρ) coeff z alpha ppAt traceAt interAt compAt
      claimed (phase2G zero one logTrace low high sizeBits sizes oods coeff z alpha
        ppPos ppAt traceAt interAt compAt claimed n).res := by
  unfold phase2G at h ⊢
  set RU := checkRelUsesG zero sizeBits 3 11 n with hRUdef
  rw [allHold_seq] at h
  rw [seq_res]
  obtain ⟨hRU, h⟩ := h
  beta_reduce at h ⊢
  set US := unpackFrom sizes 11 0 RU.next with hUSdef
  rw [allHold_seq] at h
  rw [seq_res]
  obtain ⟨hUS, h⟩ := h
  beta_reduce at h ⊢
  set NB := nbitsG sizeBits nbitAtoms.toList US.next with hNBdef
  rw [allHold_seq] at h
  rw [seq_res]
  obtain ⟨hNB, h⟩ := h
  beta_reduce at h ⊢
  set MO := mixQm31sG low high (oodsVals ppAt traceAt interAt compAt) NB.next with hMOdef
  rw [allHold_seq] at h
  rw [seq_res]
  obtain ⟨hMO, h⟩ := h
  beta_reduce at h ⊢
  set CP := compositionG zero one (dagInRegs oods.x ppPos ppAt traceAt interAt coeff z alpha claimed US.res NB.res) oods.x logTrace MO.next with hCPdef
  rw [allHold_seq] at h
  rw [seq_res]
  obtain ⟨hCP, h⟩ := h
  beta_reduce at h ⊢
  set EX := extractExpectedCompositionEvalG one (fun i => compAt.getD i 0) oods.x (logTrace + 1) CP.next with hEXdef
  rw [allHold_seq] at h
  rw [seq_res]
  obtain ⟨hEX, h⟩ := h
  beta_reduce at h ⊢
  show P2Spec ρ layout logSizes logTrace s (oods.val ρ) coeff z alpha ppAt traceAt interAt
    compAt claimed MO.res
  have heq : ρ CP.res = ρ EX.res := h _ List.mem_cons_self
  have hlsEq : (List.range 11).map (fun j => logSizes.getD j 0) = logSizes := by
    refine List.ext_getElem (by simp [hlsl]) fun j h1 h2 => ?_
    simp [List.getD_eq_getElem?_getD, List.getElem?_eq_getElem h2]
  -- Relation uses.
  have hru := checkRelUsesG_sound (fun j => logSizes.getD j 0) hzero (by norm_num)
    (by rw [hsbl]; exact hlT) (by rw [hsbl]; exact hlT31) hsbs
    (fun j hj => by rw [hsbl]; have := hlv j hj; omega)
    (fun j hj t ht => hsb j hj t (by rw [hsbl] at ht; exact ht)) hRU
  rw [hlsEq] at hru
  -- The OODS mix.
  have hmix := mixQm31sG_sound (xs := (oodsVals ppAt traceAt interAt compAt).map ρ) hd hdlen
    (by simp) (fun i hi => by
      rw [List.getD_eq_getElem?_getD, List.getD_eq_getElem?_getD, List.getElem?_map,
        List.getElem?_eq_getElem hi]; rfl) hMO
  -- Sizes and n-instance bits.
  obtain ⟨husl, husv⟩ := unpackFrom_sound 11 0 RU.next hUS
  obtain ⟨hnbl, hnbv⟩ := nbitsG_sound nbitAtoms.toList US.next hNB
  -- The DAG inputs.
  have hinputs : (dagInRegs oods.x ppPos ppAt traceAt interAt coeff z alpha claimed US.res
      NB.res).map ρ = specInputs ρ (oods.val ρ) ppPos ppAt traceAt interAt (ρ coeff) (ρ z)
        (ρ alpha) (claimed.map ρ) logSizes := by
    unfold dagInRegs specInputs
    simp only [Array.map_append, List.map_toArray, List.map_map]
    congr 2
    · refine congrArg List.toArray (List.ext_getElem
        (by rw [List.length_map, List.length_map, husl, hlsl]) fun j h1 h2 => ?_)
      have hj : j < 11 := by rw [List.length_map, husl] at h1; exact h1
      have hj' : j < logSizes.length := by rw [hlsl]; exact hj
      rw [List.getElem_map, List.getElem_map,
        ← List.getD_eq_getElem US.res 0 (by rw [husl]; exact hj), husv j hj, Nat.zero_add,
        hsz j hj, show logSizes[j] = logSizes.getD j 0 by
          rw [List.getD_eq_getElem?_getD, List.getElem?_eq_getElem hj']; rfl]
      push_cast; rfl
    · refine List.ext_getElem (by rw [List.length_map, List.length_map, hnbl]) fun k h1 h2 => ?_
      have hk5 : k < nbitAtoms.toList.length := by rw [List.length_map, hnbl] at h1; exact h1
      rw [List.getElem_map, List.getElem_map,
        ← List.getD_eq_getElem NB.res 0 (by rw [hnbl]; exact hk5), hnbv k hk5,
        List.getD_eq_getElem _ _ hk5]
      have hmem := List.getElem_mem hk5
      have hall : ∀ x ∈ nbitAtoms.toList, x.1 < 11 ∧ x.2 < 19 := by decide
      obtain ⟨hc, hb⟩ := hall _ hmem
      rw [hsb _ hc _ (by omega)]
      by_cases he : nbitAtoms.toList[k].2 = logSizes.getD nbitAtoms.toList[k].1 0
      · rw [if_pos he, if_pos he.symm]; rfl
      · rw [if_neg he, if_neg (Ne.symm he)]; rfl
  have hin' : ∀ a, ρ ((dagInRegs oods.x ppPos ppAt traceAt interAt coeff z alpha claimed US.res
      NB.res).getD a zero) = (specInputs ρ (oods.val ρ) ppPos ppAt traceAt interAt (ρ coeff)
        (ρ z) (ρ alpha) (claimed.map ρ) logSizes).getD a QM31.zero := by
    intro a; rw [arr_getD_map ρ zero hzero, hinputs]
  obtain ⟨heqs, hcomp⟩ := compositionG_sound hzero hone hin'
    (by unfold specInputs; simp [atomPtX, PointReg.val, Array.getD_eq_getD_getElem?]) hCP
  -- The extracted value.
  have hex := extractExpected_matches_spec hone (by omega) hP rfl hEX
  rw [show logTrace + 1 - 1 + 1 = logTrace + 1 by omega] at hex
  refine ⟨hru, hmix, ρ EX.res, ?_, ?_⟩
  · rw [extract_ok ρ ppAt traceAt interAt compAt _ _ hcmp (by omega)]
    exact hex
  · rw [evalComposition_eq, ← hppPos, flatInputs_ok ρ _ ppPos ppAt traceAt interAt compAt _ _ _ _
      logSizes hpp hpos hposlt htr hin hkinds (by simp [hcl]) hlsl, Quotients.ok_bind,
      if_neg (fun hc => hc heqs)]
    show Except.ok _ = _
    rw [← hcomp, heq]

end StwoVerifier.Gadgets
