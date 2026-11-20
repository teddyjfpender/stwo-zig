/-
**Phase 6, spec side: the per-query FRI facts give an accepting
`Fri.decommit`.**

The raw queries' layer views (`qsOf`) are the `FriBatch.FQ`s; their
paths, folds and links come from `P6Facts`; the read-off witnesses
(`fwit`, `MerkleBatch.wits`) and the collision hypotheses are stated on
`qsOf` with the fold output zeroed, which neither depends on.
-/
import StwoVerifier.PhaseFri

namespace StwoVerifier.Bridge

open StwoVerifier StwoVerifier.Gadgets StwoVerifier.Gates FriBatch MerkleBatch

section
variable (ρ : ℕ → QM31) (nq : ℕ) (pos : ℕ → ℕ) (wit : ℕ → ℕ → ℕ × ℕ)
  (sws : ℕ → ℕ → List (List Blake2s.Word))

/-- Query `i`'s view of layer `l`, with fold outputs `o`. -/
noncomputable def fqOf (o : ℕ → ℕ → QM31) (l i : ℕ) : FQ :=
  ⟨pos i / 2 ^ l, ρ (wit l i).1, ρ (wit l i).2, (sws l i).map wordsBytes, o (l + 1) i⟩

/-- Layer `l`'s raw queries. -/
noncomputable def qsOf (o : ℕ → ℕ → QM31) (l : ℕ) : List FQ :=
  (List.range nq).map (fqOf ρ pos wit sws o l)

theorem C0_qsOf (o : ℕ → ℕ → QM31) (l k : ℕ) :
    C0 (qsOf ρ nq pos wit sws o l) k
      = ((List.range nq).find? (fun i => decide (pos i / 2 ^ l / 2 = k))).elim 0
          (fun i => ρ (wit l i).1) := by
  unfold C0 qsOf
  rw [List.find?_map]
  show (match Option.map _ (List.find? (fun i => decide (pos i / 2 ^ l / 2 = k))
    (List.range nq)) with | some q => FQ.w0 q | none => 0) = _
  cases List.find? (fun i => decide (pos i / 2 ^ l / 2 = k)) (List.range nq) <;> rfl

theorem C1_qsOf (o : ℕ → ℕ → QM31) (l k : ℕ) :
    C1 (qsOf ρ nq pos wit sws o l) k
      = ((List.range nq).find? (fun i => decide (pos i / 2 ^ l / 2 = k))).elim 0
          (fun i => ρ (wit l i).2) := by
  unfold C1 qsOf
  rw [List.find?_map]
  show (match Option.map _ (List.find? (fun i => decide (pos i / 2 ^ l / 2 = k))
    (List.range nq)) with | some q => FQ.w1 q | none => 0) = _
  cases List.find? (fun i => decide (pos i / 2 ^ l / 2 = k)) (List.range nq) <;> rfl

theorem fwit_out (o o' : ℕ → ℕ → QM31) (l : ℕ) :
    ∀ ps, fwit (qsOf ρ nq pos wit sws o l) ps = fwit (qsOf ρ nq pos wit sws o' l) ps
  | [] => rfl
  | [p] => by simp only [fwit, C0_qsOf, C1_qsOf]
  | p :: p' :: rest => by
    simp only [fwit, C0_qsOf, C1_qsOf]
    rw [fwit_out o o' l rest, fwit_out o o' l (p' :: rest)]

theorem allMQ_out (o o' : ℕ → ℕ → QM31) (l : ℕ) :
    allMQ (qsOf ρ nq pos wit sws o l) = allMQ (qsOf ρ nq pos wit sws o' l) := by
  simp [allMQ, qsOf, FQ.mqs, fqOf, List.flatMap_map]

theorem leafInj_out {o o' : ℕ → ℕ → QM31} {l : ℕ}
    (h : LeafInj (qsOf ρ nq pos wit sws o l)) : LeafInj (qsOf ρ nq pos wit sws o' l) := by
  intro q hq q' hq'
  unfold qsOf at hq hq'
  obtain ⟨i, hi, rfl⟩ := List.mem_map.mp hq
  obtain ⟨i', hi', rfl⟩ := List.mem_map.mp hq'
  exact h (fqOf ρ pos wit sws o l i) (List.mem_map.mpr ⟨i, hi, rfl⟩)
    (fqOf ρ pos wit sws o l i') (List.mem_map.mpr ⟨i', hi', rfl⟩)

end

theorem iter_double_logSize (d : LineDomain) : ∀ l, (LineDomain.double^[l] d).logSize = d.logSize - l
  | 0 => rfl
  | l + 1 => by
    rw [Function.iterate_succ_apply', show (LineDomain.double (LineDomain.double^[l] d)).logSize
      = (LineDomain.double^[l] d).logSize - 1 from rfl, iter_double_logSize d l]
    omega

theorem mem_par_iter {uniq : List ℕ} {nq : ℕ} {pos : ℕ → ℕ}
    (hu : ∀ p, p ∈ uniq ↔ ∃ i, i < nq ∧ pos i = p) :
    ∀ k p, p ∈ par^[k] uniq ↔ ∃ i, i < nq ∧ pos i / 2 ^ k = p
  | 0, p => by simpa using hu p
  | k + 1, p => by
    rw [Function.iterate_succ_apply', mem_par']
    constructor
    · rintro ⟨x, hx, rfl⟩
      obtain ⟨i, hi, rfl⟩ := (mem_par_iter hu k x).mp hx
      exact ⟨i, hi, by rw [pow_succ, ← Nat.div_div_eq_div_mul]⟩
    · rintro ⟨i, hi, rfl⟩
      exact ⟨pos i / 2 ^ k, (mem_par_iter hu k _).mpr ⟨i, hi, rfl⟩,
        by rw [pow_succ, ← Nat.div_div_eq_div_mul]⟩

theorem par_iter_sorted {uniq : List ℕ} (hs : uniq.Pairwise (· < ·)) :
    ∀ k, (par^[k] uniq).Pairwise (· < ·)
  | 0 => hs
  | k + 1 => by
    rw [Function.iterate_succ_apply']
    exact par_sorted _ _ le_rfl (par_iter_sorted hs k)

theorem canonic_logSize {L : ℕ} (hL : 1 ≤ L) : (canonicDomain L).logSize = L := by
  show (L - 1) + 1 = L
  omega

theorem foldCircle_eq {L : ℕ} (hL : 1 ≤ L) (α : QM31) (s : ℕ) (a b : QM31) :
    Fri.foldCircleSubset (canonicDomain L) α ⟨s, [a, b]⟩
      = Fri.foldLinePair a b α ((canonicDomain L).at' (bitReverseIndex s L)).y := by
  unfold Fri.foldCircleSubset
  rw [canonic_logSize hL]

theorem foldLine_eq (d : LineDomain) (α : QM31) (s : ℕ) (a b : QM31) :
    Fri.foldLineSubset d α ⟨s, [a, b]⟩
      = Fri.foldLinePair a b α (d.coset.indexAt (bitReverseIndex s d.logSize)).toPoint.x := rfl

theorem lq_length (v : QM31) : (lq v).length = 32 := blake2s_length _

section
variable {ρ : ℕ → QM31} {nq L : ℕ} {pos : ℕ → ℕ} {wit : ℕ → ℕ → ℕ × ℕ}
  {sws : ℕ → ℕ → List (List Blake2s.Word)} {wr : ℕ → List Blake2s.Word}

theorem mem_allMQ {o : ℕ → ℕ → QM31} {l : ℕ} {q : MQ}
    (hq : q ∈ allMQ (qsOf ρ nq pos wit sws o l)) :
    ∃ i, i < nq ∧ q ∈ (fqOf ρ pos wit sws o l i).mqs := by
  unfold allMQ qsOf at hq
  rw [List.flatMap_map] at hq
  obtain ⟨i, hi, hq⟩ := List.mem_flatMap.mp hq
  exact ⟨i, List.mem_range.mp hi, hq⟩

/-- **Layer `l`'s raw queries authenticate to its root.** -/
theorem layerPaths (o : ℕ → ℕ → QM31) {l : ℕ} (hl : l < L - 1)
    (hposL : ∀ i, i < nq → pos i < 2 ^ L)
    (hroot : ∀ i, i < nq → wordsBytes (wr l) = pathRoot
      (Merkle.nodeHash (lq (ρ (wit l i).1)) (lq (ρ (wit l i).2)))
      ((List.range (L - 1 - l)).map fun t => pos i / 2 ^ (l + 1 + t) % 2)
      ((sws l i).map wordsBytes))
    (hsl : ∀ i, i < nq → (sws l i).length = L - 1 - l)
    (hs8 : ∀ i, i < nq → ∀ k, k < (sws l i).length → ((sws l i).getD k []).length = 8)
    (hinj : ∀ q ∈ allMQ (qsOf ρ nq pos wit sws (fun _ _ => 0) l),
      ∀ q' ∈ allMQ (qsOf ρ nq pos wit sws (fun _ _ => 0) l), ∀ k, k < L - l →
        Blake2s.blake2s (msg q k) = Blake2s.blake2s (msg q' k) → msg q k = msg q' k) :
    Paths (allMQ (qsOf ρ nq pos wit sws o l)) (L - l) (wordsBytes (wr l)) := by
  rw [allMQ_out ρ nq pos wit sws o (fun _ _ => 0) l]
  have hP : ∀ i, i < nq → pos i / 2 ^ l < 2 ^ (L - l) := by
    intro i hi
    rw [Nat.div_lt_iff_lt_mul (by positivity), ← pow_add, show L - l + l = L by omega]
    exact hposL i hi
  refine ⟨fun q hq => ?_, fun q hq => ?_, fun q hq => ?_, fun q hq k hk => ?_, hinj⟩
  · obtain ⟨i, hi, hq⟩ := mem_allMQ hq
    have h1 := hP i hi
    have hev : 2 ^ (L - l) % 2 = 0 := by
      rw [show L - l = (L - l - 1) + 1 by omega, pow_succ]; simp
    simp only [FQ.mqs, fqOf, List.mem_cons, List.not_mem_nil, or_false] at hq
    rcases hq with rfl | rfl <;> simp only <;> omega
  · obtain ⟨i, hi, hq⟩ := mem_allMQ hq
    have := cosetMQ_root (fqOf ρ pos wit sws (fun _ _ => 0) l i) (h := L - l) (by omega)
      (by simp [fqOf, hsl i hi]; omega) q hq
    rw [this, hroot i hi]
    simp only [fqOf]
    congr 1
    rw [show L - l - 1 = L - 1 - l by omega]
    refine List.map_congr_left fun t _ => ?_
    rw [Nat.div_div_eq_div_mul, ← pow_add, show l + (t + 1) = l + 1 + t by omega]
  · obtain ⟨i, hi, hq⟩ := mem_allMQ hq
    simp only [FQ.mqs, fqOf, List.mem_cons, List.not_mem_nil, or_false] at hq
    rcases hq with rfl | rfl <;> exact lq_length _
  · obtain ⟨i, hi, hq⟩ := mem_allMQ hq
    have hauth : ∀ k, k + 1 < L - l →
        (((sws l i).map wordsBytes).getD k []).length = 32 := by
      intro k hk'
      have hk2 : k < (sws l i).length := by rw [hsl i hi]; omega
      rw [List.getD_eq_getElem?_getD, List.getElem?_map, List.getElem?_eq_getElem hk2]
      simp only [Option.map_some, Option.getD_some]
      rw [wordsBytes_length, ← List.getD_eq_getElem _ [] hk2, hs8 i hi k hk2]
    simp only [FQ.mqs, fqOf, List.mem_cons, List.not_mem_nil, or_false] at hq
    rcases hq with rfl | rfl <;>
    · cases k with
      | zero => exact lq_length _
      | succ k => exact hauth k hk

end

/-- Everything the spec-side FRI argument consumes: the `P6Facts` body
for a value table `V`, the query shape, and the collision hypotheses. -/
structure FriH (ρ : ℕ → QM31) (nq L : ℕ) (pos : ℕ → ℕ) (wit : ℕ → ℕ → ℕ × ℕ)
    (sws : ℕ → ℕ → List (List Blake2s.Word)) (wr : ℕ → List Blake2s.Word)
    (alphas : List ℕ) (lastCoef : ℕ) (uniq : List ℕ) (V : ℕ → ℕ → QM31) : Prop where
  hL2 : 2 ≤ L
  hL30 : L ≤ 30
  hposL : ∀ i, i < nq → pos i < 2 ^ L
  hu : ∀ p, p ∈ uniq ↔ ∃ i, i < nq ∧ pos i = p
  hs : uniq.Pairwise (· < ·)
  hnq : 0 < nq
  sel : ∀ l, l < L - 1 → ∀ i, i < nq →
    V l i = (if pos i / 2 ^ l % 2 = 0 then ρ (wit l i).1 else ρ (wit l i).2)
  fold : ∀ l, l < L - 1 → ∀ i, i < nq →
    Fri.foldLinePair (ρ (wit l i).1) (ρ (wit l i).2) (ρ (alphas.getD l 0))
      (specFoldCoord (fun t => pos i / 2 ^ t % 2) L l) = .ok (V (l + 1) i)
  root : ∀ l, l < L - 1 → ∀ i, i < nq → wordsBytes (wr l) = pathRoot
    (Merkle.nodeHash (lq (ρ (wit l i).1)) (lq (ρ (wit l i).2)))
    ((List.range (L - 1 - l)).map fun t => pos i / 2 ^ (l + 1 + t) % 2)
    ((sws l i).map wordsBytes)
  last : ∀ i, i < nq → V (L - 1) i = ρ lastCoef
  sl : ∀ l, l < L - 1 → ∀ i, i < nq → (sws l i).length = L - 1 - l
  s8 : ∀ l, l < L - 1 → ∀ i, i < nq → ∀ k, k < (sws l i).length →
    ((sws l i).getD k []).length = 8
  inj : ∀ l, l < L - 1 → ∀ q ∈ allMQ (qsOf ρ nq pos wit sws (fun _ _ => 0) l),
    ∀ q' ∈ allMQ (qsOf ρ nq pos wit sws (fun _ _ => 0) l), ∀ k, k < L - l →
      Blake2s.blake2s (msg q k) = Blake2s.blake2s (msg q' k) → msg q k = msg q' k
  leaf : ∀ l, l < L - 1 → LeafInj (qsOf ρ nq pos wit sws (fun _ _ => 0) l)

/-- The read-off inner layer `l` (folding into layer `l + 1`). -/
noncomputable def friEntry (ρ : ℕ → QM31) (nq L : ℕ) (pos : ℕ → ℕ) (wit : ℕ → ℕ → ℕ × ℕ)
    (sws : ℕ → ℕ → List (List Blake2s.Word)) (wr : ℕ → List Blake2s.Word)
    (alphas uniq : List ℕ) (l : ℕ) : LineDomain × QM31 × Fri.FriLayerProof :=
  (LineDomain.double^[l] ⟨Coset.halfOdds (L - 1)⟩, ρ (alphas.getD (l + 1) 0),
    ⟨fwit (qsOf ρ nq pos wit sws (fun _ _ => 0) (l + 1)) (par^[l + 1] uniq),
     wits (allMQ (qsOf ρ nq pos wit sws (fun _ _ => 0) (l + 1)))
       ((par (par^[l + 1] uniq)).flatMap fun k => [k * 2, k * 2 + 1]) 0 (L - (l + 1)),
     wordsBytes (wr (l + 1))⟩)

section
variable {ρ : ℕ → QM31} {nq L : ℕ} {pos : ℕ → ℕ} {wit : ℕ → ℕ → ℕ × ℕ}
  {sws : ℕ → ℕ → List (List Blake2s.Word)} {wr : ℕ → List Blake2s.Word}
  {alphas : List ℕ} {lastCoef : ℕ} {uniq : List ℕ} {V : ℕ → ℕ → QM31}

theorem FriH.paths (H : FriH ρ nq L pos wit sws wr alphas lastCoef uniq V) {l : ℕ}
    (hl : l < L - 1) :
    Paths (allMQ (qsOf ρ nq pos wit sws V l)) (L - l) (wordsBytes (wr l)) :=
  layerPaths V hl H.hposL (H.root l hl) (H.sl l hl) (H.s8 l hl) (H.inj l hl)

theorem FriH.leafV (H : FriH ρ nq L pos wit sws wr alphas lastCoef uniq V) {l : ℕ}
    (hl : l < L - 1) : LeafInj (qsOf ρ nq pos wit sws V l) :=
  leafInj_out ρ nq pos wit sws (H.leaf l hl)

theorem mem_qsOf {o : ℕ → ℕ → QM31} {l : ℕ} {q : FQ} (hq : q ∈ qsOf ρ nq pos wit sws o l) :
    ∃ i, i < nq ∧ q = fqOf ρ pos wit sws o l i := by
  unfold qsOf at hq
  obtain ⟨i, hi, rfl⟩ := List.mem_map.mp hq
  exact ⟨i, List.mem_range.mp hi, rfl⟩

theorem fq_mem {o : ℕ → ℕ → QM31} {l i : ℕ} (hi : i < nq) :
    fqOf ρ pos wit sws o l i ∈ qsOf ρ nq pos wit sws o l :=
  List.mem_map.mpr ⟨i, List.mem_range.mpr hi, rfl⟩

/-- Every layer's raw queries fold, through some subset fold. -/
theorem FriH.outFold (H : FriH ρ nq L pos wit sws wr alphas lastCoef uniq V) {l : ℕ}
    (hl : l < L - 1) :
    ∃ fold : Fri.Subset → Except VError QM31, ∀ q ∈ qsOf ρ nq pos wit sws V l,
      fold ⟨q.pos / 2 * 2, [q.w0, q.w1]⟩ = .ok q.out := by
  cases l with
  | zero =>
    refine ⟨Fri.foldCircleSubset (canonicDomain L) (ρ (alphas.getD 0 0)), fun q hq => ?_⟩
    obtain ⟨i, hi, rfl⟩ := mem_qsOf hq
    rw [foldCircle_eq (by have := H.hL2; omega)]
    have := H.fold 0 hl i hi
    rw [specFoldCoord_circle (H.hposL i hi) (by have := H.hL2; omega)] at this
    simpa [fqOf] using this
  | succ k =>
    refine ⟨Fri.foldLineSubset (LineDomain.double^[k] ⟨Coset.halfOdds (L - 1)⟩)
      (ρ (alphas.getD (k + 1) 0)), fun q hq => ?_⟩
    obtain ⟨i, hi, rfl⟩ := mem_qsOf hq
    rw [foldLine_eq, iter_double_logSize]
    have := H.fold (k + 1) hl i hi
    rw [specFoldCoord_line (H.hposL i hi) (by omega)] at this
    rw [show (⟨Coset.halfOdds (L - 1)⟩ : LineDomain).logSize - k = L - (k + 1) from by
      show L - 1 - k = L - (k + 1); omega]
    exact this

/-- The layer value at a raw query's position is its selected coset entry. -/
theorem FriH.cv (H : FriH ρ nq L pos wit sws wr alphas lastCoef uniq V) {l : ℕ}
    (hl : l < L - 1) {i : ℕ} (hi : i < nq) :
    Cv (qsOf ρ nq pos wit sws V l) (pos i / 2 ^ l) = V l i := by
  obtain ⟨h0, h1⟩ := C_of_mem (H.paths hl) (H.leafV hl) (fq_mem (o := V) (l := l) hi)
    (k := pos i / 2 ^ l / 2) rfl
  rw [H.sel l hl i hi]
  unfold Cv
  by_cases hz : pos i / 2 ^ l % 2 = 0
  · rw [if_pos hz, if_pos hz, h0]; rfl
  · rw [if_neg hz, if_neg hz, h1]; rfl

/-- The inner layer `k + 1`'s `LayerOK`. -/
theorem FriH.layerOK (H : FriH ρ nq L pos wit sws wr alphas lastCoef uniq V) {k : ℕ}
    (hk : k + 1 < L - 1) :
    LayerOK (friEntry ρ nq L pos wit sws wr alphas uniq k).1.logSize
      (Fri.foldLineSubset (friEntry ρ nq L pos wit sws wr alphas uniq k).1
        (friEntry ρ nq L pos wit sws wr alphas uniq k).2.1)
      (friEntry ρ nq L pos wit sws wr alphas uniq k).2.2.commitment
      (friEntry ρ nq L pos wit sws wr alphas uniq k).2.2.friWitness
      (friEntry ρ nq L pos wit sws wr alphas uniq k).2.2.hashWitness
      (qsOf ρ nq pos wit sws V k) (qsOf ρ nq pos wit sws V (k + 1)) (par^[k] uniq) := by
  have hls : (friEntry ρ nq L pos wit sws wr alphas uniq k).1.logSize = L - (k + 1) := by
    show (LineDomain.double^[k] ⟨Coset.halfOdds (L - 1)⟩).logSize = _
    rw [iter_double_logSize]
    show L - 1 - k = _; omega
  have hpar : par (par^[k] uniq) = par^[k + 1] uniq := (Function.iterate_succ_apply' _ _ _).symm
  rw [hls]
  refine ⟨H.paths hk, H.leafV hk, fun q hq => ?_, fun p hp => ?_, fun p hp => ?_, ?_, ?_⟩
  · obtain ⟨i, hi, rfl⟩ := mem_qsOf hq
    show Fri.foldLineSubset (LineDomain.double^[k] ⟨Coset.halfOdds (L - 1)⟩)
      (ρ (alphas.getD (k + 1) 0)) _ = _
    rw [foldLine_eq, iter_double_logSize]
    have := H.fold (k + 1) hk i hi
    rw [specFoldCoord_line (H.hposL i hi) (by omega)] at this
    rw [show (⟨Coset.halfOdds (L - 1)⟩ : LineDomain).logSize - k = L - (k + 1) from by
      show L - 1 - k = L - (k + 1); omega]
    exact this
  · rw [hpar] at hp
    obtain ⟨i, hi, rfl⟩ := (mem_par_iter H.hu (k + 1) p).mp hp
    exact ⟨_, fq_mem (o := V) (l := k + 1) hi, rfl⟩
  · rw [hpar] at hp
    obtain ⟨i, hi, rfl⟩ := (mem_par_iter H.hu (k + 1) p).mp hp
    obtain ⟨fold, hfold⟩ := H.outFold (l := k) (by omega)
    rw [O_of_mem (H.paths (l := k) (by omega)) (H.leafV (l := k) (by omega)) fold hfold
      (fq_mem (o := V) (l := k) hi) (k := pos i / 2 ^ (k + 1))
      (by show pos i / 2 ^ k / 2 = _; rw [Nat.div_div_eq_div_mul, ← pow_succ]),
      H.cv hk hi]
    rfl
  · rw [hpar]
    show fwit (qsOf ρ nq pos wit sws (fun _ _ => 0) (k + 1)) (par^[k + 1] uniq) = _
    exact fwit_out ρ nq pos wit sws _ _ _ _
  · rw [hpar]
    show wits (allMQ (qsOf ρ nq pos wit sws (fun _ _ => 0) (k + 1))) _ 0 (L - (k + 1)) = _
    rw [allMQ_out ρ nq pos wit sws (fun _ _ => 0) V]

theorem FriH.innerOK (H : FriH ρ nq L pos wit sws wr alphas lastCoef uniq V) :
    ∀ m k, k + m = L - 2 →
      InnerOK ((List.range m).map fun j => friEntry ρ nq L pos wit sws wr alphas uniq (k + j))
        (qsOf ρ nq pos wit sws V k) (par^[k] uniq) (qsOf ρ nq pos wit sws V (L - 2))
  | 0, k, hkm => by
    obtain rfl : k = L - 2 := by omega
    exact InnerOK.nil _ _
  | m + 1, k, hkm => by
    rw [List.range_succ_eq_map, List.map_cons, List.map_map]
    have hrest := H.innerOK m (k + 1) (by omega)
    rw [show ((fun j => friEntry ρ nq L pos wit sws wr alphas uniq (k + j)) ∘ Nat.succ)
      = fun j => friEntry ρ nq L pos wit sws wr alphas uniq (k + 1 + j) from
        funext fun j => by simp only [Function.comp, Nat.succ_eq_add_one]; congr 1; omega]
    have hl := H.layerOK (k := k) (by have := H.hL2; omega)
    rw [Nat.add_zero]
    rw [Function.iterate_succ_apply'] at hrest
    exact InnerOK.cons (friEntry ρ nq L pos wit sws wr alphas uniq k).1
      (friEntry ρ nq L pos wit sws wr alphas uniq k).2.1
      (friEntry ρ nq L pos wit sws wr alphas uniq k).2.2 _ _ _ _ _ hl hrest

/-- **The FRI decommitment accepts** on the read-off proof, at the
unique positions, with the raw query values as the layer-0 evaluations. -/
theorem FriH.decommit (H : FriH ρ nq L pos wit sws wr alphas lastCoef uniq V)
    (c : Fri.Committed)
    (hdom : c.columnCommitmentDomain = canonicDomain L)
    (hα0 : c.firstAlpha = ρ (alphas.getD 0 0))
    (hfp : c.firstProof =
      ⟨fwit (qsOf ρ nq pos wit sws (fun _ _ => 0) 0) uniq,
       wits (allMQ (qsOf ρ nq pos wit sws (fun _ _ => 0) 0))
         ((par uniq).flatMap fun k => [k * 2, k * 2 + 1]) 0 L,
       wordsBytes (wr 0)⟩)
    (hinner : c.innerLayers = (List.range (L - 2)).map
      (friEntry ρ nq L pos wit sws wr alphas uniq))
    (hpoly : c.lastLayerPoly = [ρ lastCoef]) :
    Fri.decommit c uniq (uniq.map (Cv (qsOf ρ nq pos wit sws V 0))) = .ok () := by
  have hL1 : 1 ≤ L := by have := H.hL2; omega
  have hl0 : 0 < L - 1 := by have := H.hL2; omega
  have hne : uniq ≠ [] := by
    intro he
    have := (H.hu (pos 0)).mpr ⟨0, H.hnq, rfl⟩
    rw [he] at this; simp at this
  have hls : c.columnCommitmentDomain.logSize = L := by rw [hdom, canonic_logSize hL1]
  obtain ⟨fold0, hfold0⟩ := H.outFold hl0
  refine decommit_ok c H.hs hne
    (fun p hp => by
      obtain ⟨i, hi, rfl⟩ := (H.hu p).mp hp
      exact ⟨_, fq_mem (o := V) (l := 0) hi, by simp [fqOf]⟩)
    (by rw [hls, hfp]; simpa using H.paths hl0) (H.leafV hl0)
    (fun q hq => by
      obtain ⟨i, hi, rfl⟩ := mem_qsOf hq
      rw [hdom, hα0, foldCircle_eq hL1]
      have := H.fold 0 hl0 i hi
      rw [specFoldCoord_circle (H.hposL i hi) hL1] at this
      simpa [fqOf] using this)
    (by rw [hfp]; exact fwit_out ρ nq pos wit sws _ _ _ _)
    (by rw [hfp, hls, allMQ_out ρ nq pos wit sws (fun _ _ => 0) V])
    (by
      rw [hinner]
      have := H.innerOK (L - 2) 0 (by omega)
      simpa using this)
    hpoly
    (fun q hq => by
      obtain ⟨i, hi, rfl⟩ := mem_qsOf hq
      show V (L - 2 + 1) i = _
      rw [show L - 2 + 1 = L - 1 by have := H.hL2; omega]
      exact H.last i hi)

/-- The raw FRI inputs are the layer-0 evaluations at the raw positions. -/
theorem FriH.cv0 (H : FriH ρ nq L pos wit sws wr alphas lastCoef uniq V) {i : ℕ}
    (hi : i < nq) : Cv (qsOf ρ nq pos wit sws V 0) (pos i) = V 0 i := by
  have := H.cv (l := 0) (by have := H.hL2; omega) hi
  simpa using this

end

end StwoVerifier.Bridge
