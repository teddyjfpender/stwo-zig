/-
**Per-query FRI cosets give an accepting spec decommitment** (fold
step 1).

Per layer and raw query, the in-circuit `fri_decommit` guesses the
query's two-element coset, checks the incoming value is the coset entry
its position bit selects, hashes the coset into a node and authenticates
that node along the query's auth path, and folds the coset. The spec
(`Fri.decommit`) instead walks the sorted unique positions: it rebuilds
each opened subset from the incoming evaluations and a witness of
absent siblings (`rebuildSubsets`), Merkle-verifies all subsets at once
(`verifyLayerMerkle`), and folds each subset.

`layer_ok` proves one spec layer accepts on explicit witnesses
(`fwit`, `MerkleBatch.wits`) and folds to the raw queries' outputs: each
raw query becomes two Merkle queries (both coset leaves, each the
other's sibling), so `MerkleBatch.verify_paths` applies to the subsets'
flat position list; the Merkle consistency at the leaves plus the leaf
collision hypothesis make all raw queries through one subset agree on
its coset (`coset_consist`).
-/
import StwoVerifier.MerkleBatch
import StwoVerifier.Fri
import StwoVerifier.SpecLemmas

namespace StwoVerifier.FriBatch

open StwoVerifier MerkleBatch Merkle Channel

/-- The FRI leaf hash of one QM31: its four coordinates as one row. -/
def lq (v : QM31) : Bytes := leafHash v.coords

/-- One raw query's view of one fold-step-1 layer: its position in the
layer, its guessed coset, the auth path above the coset node, and its
fold output. -/
structure FQ where
  pos : ℕ
  w0 : QM31
  w1 : QM31
  auth : List Bytes
  out : QM31

/-- The coset's two leaves as Merkle queries, each the other's sibling. -/
def FQ.mqs (q : FQ) : List MQ :=
  [⟨q.pos / 2 * 2, lq q.w0, lq q.w1 :: q.auth⟩,
   ⟨q.pos / 2 * 2 + 1, lq q.w1, lq q.w0 :: q.auth⟩]

def allMQ (qs : List FQ) : List MQ := qs.flatMap FQ.mqs

/-- The leaf-level collision hypothesis of one layer: equal FRI leaf
hashes of coset entries mean equal entries. -/
def LeafInj (qs : List FQ) : Prop :=
  ∀ q ∈ qs, ∀ q' ∈ qs,
    (lq q.w0 = lq q'.w0 → q.w0 = q'.w0) ∧ (lq q.w1 = lq q'.w1 → q.w1 = q'.w1)

theorem mq0_mem {qs : List FQ} {q : FQ} (hq : q ∈ qs) :
    (⟨q.pos / 2 * 2, lq q.w0, lq q.w1 :: q.auth⟩ : MQ) ∈ allMQ qs :=
  List.mem_flatMap.mpr ⟨q, hq, List.mem_cons_self⟩

theorem mq1_mem {qs : List FQ} {q : FQ} (hq : q ∈ qs) :
    (⟨q.pos / 2 * 2 + 1, lq q.w1, lq q.w0 :: q.auth⟩ : MQ) ∈ allMQ qs :=
  List.mem_flatMap.mpr ⟨q, hq, List.mem_cons_of_mem _ List.mem_cons_self⟩

section
variable {qs : List FQ} {h : ℕ} {root : Bytes}

/-- **Raw queries through one subset agree on its coset.** -/
theorem coset_consist (hP : Paths (allMQ qs) h root) (hL : LeafInj qs)
    {q q' : FQ} (hq : q ∈ qs) (hq' : q' ∈ qs) (hk : q.pos / 2 = q'.pos / 2) :
    q.w0 = q'.w0 ∧ q.w1 = q'.w1 := by
  have h0 := consist' hP (Nat.zero_le h) (mq0_mem hq) (mq0_mem hq')
    (by simp only [pow_zero, Nat.div_one]; rw [hk])
  have h1 := consist' hP (Nat.zero_le h) (mq1_mem hq) (mq1_mem hq')
    (by simp only [pow_zero, Nat.div_one]; rw [hk])
  exact ⟨(hL q hq q' hq').1 h0, (hL q hq q' hq').2 h1⟩

end

/-- The subset `k`'s coset entries and fold output, read off the raw
queries. -/
def C0 (qs : List FQ) (k : ℕ) : QM31 :=
  match qs.find? (fun q => q.pos / 2 = k) with | some q => q.w0 | none => 0
def C1 (qs : List FQ) (k : ℕ) : QM31 :=
  match qs.find? (fun q => q.pos / 2 = k) with | some q => q.w1 | none => 0
def O (qs : List FQ) (k : ℕ) : QM31 :=
  match qs.find? (fun q => q.pos / 2 = k) with | some q => q.out | none => 0

/-- The layer value at position `p`. -/
def Cv (qs : List FQ) (p : ℕ) : QM31 :=
  if p % 2 = 0 then C0 qs (p / 2) else C1 qs (p / 2)

theorem find_coset {qs : List FQ} {k : ℕ} {q : FQ} (hq : q ∈ qs) (hk : q.pos / 2 = k) :
    ∃ q₁ ∈ qs, q₁.pos / 2 = k ∧ qs.find? (fun q => q.pos / 2 = k) = some q₁ := by
  cases hf : qs.find? (fun q => q.pos / 2 = k) with
  | none =>
    have := List.find?_eq_none.mp hf q hq
    simp [hk] at this
  | some q₁ =>
    have h1 := List.find?_some hf
    simp only [decide_eq_true_eq] at h1
    exact ⟨q₁, List.mem_of_find?_eq_some hf, h1, rfl⟩

section
variable {qs : List FQ} {h : ℕ} {root : Bytes}

theorem C_of_mem (hP : Paths (allMQ qs) h root) (hL : LeafInj qs) {q : FQ}
    (hq : q ∈ qs) {k : ℕ} (hk : q.pos / 2 = k) :
    C0 qs k = q.w0 ∧ C1 qs k = q.w1 := by
  obtain ⟨q₁, hq₁, hk₁, hf⟩ := find_coset hq hk
  unfold C0 C1
  rw [hf]
  exact coset_consist hP hL hq₁ hq (by rw [hk₁, hk])

theorem O_of_mem (hP : Paths (allMQ qs) h root) (hL : LeafInj qs)
    (fold : Fri.Subset → Except VError QM31)
    (hfold : ∀ q ∈ qs, fold ⟨q.pos / 2 * 2, [q.w0, q.w1]⟩ = .ok q.out)
    {q : FQ} (hq : q ∈ qs) {k : ℕ} (hk : q.pos / 2 = k) :
    O qs k = q.out := by
  obtain ⟨q₁, hq₁, hk₁, hf⟩ := find_coset hq hk
  unfold O
  rw [hf]
  obtain ⟨e0, e1⟩ := coset_consist hP hL hq₁ hq (by rw [hk₁, hk])
  have h1 := hfold q₁ hq₁
  rw [e0, e1, show q₁.pos / 2 = q.pos / 2 by rw [hk₁, hk], hfold q hq] at h1
  exact (Except.ok.inj h1).symm

end

/-! ### `rebuildSubsets` -/

/-- The witness values `rebuildSubsets` consumes: each absent sibling's
coset entry, in the spec's order. -/
def fwit (qs : List FQ) : List ℕ → List QM31
  | [] => []
  | [p] => [if p % 2 = 0 then C1 qs (p / 2) else C0 qs (p / 2)]
  | p :: p' :: rest =>
    if p % 2 = 0 ∧ p' = p + 1 then fwit qs rest
    else (if p % 2 = 0 then C1 qs (p / 2) else C0 qs (p / 2)) :: fwit qs (p' :: rest)

/-- The rebuilt subsets: one per parent index. -/
def subsOf (qs : List FQ) (ks : List ℕ) : List Fri.Subset :=
  ks.map fun k => ⟨k * 2, [C0 qs k, C1 qs k]⟩

theorem cv_even (qs : List FQ) {p : ℕ} (hp : p % 2 = 0) : Cv qs p = C0 qs (p / 2) := by
  unfold Cv; rw [if_pos hp]

theorem cv_odd (qs : List FQ) {p : ℕ} (hp : p % 2 = 1) : Cv qs p = C1 qs (p / 2) := by
  unfold Cv; rw [if_neg (by omega)]

theorem merge_iff {p p' : ℕ} (hlt : p < p') : p ^^^ 1 = p' ↔ (p % 2 = 0 ∧ p' = p + 1) := by
  rcases Nat.even_or_odd' p with ⟨k, rfl | rfl⟩
  · rw [xor_one_even]; omega
  · rw [xor_one_odd]; omega

theorem go_ok (qs : List FQ) :
    ∀ (n : ℕ) (ps : List ℕ), ps.length ≤ n → ps.Pairwise (· < ·) → ∀ rest,
      Fri.rebuildSubsets.go (ps.map fun p => (p, Cv qs p)) (fwit qs ps ++ rest)
        = .ok (subsOf qs (par ps), rest) := by
  intro n
  induction n with
  | zero =>
    intro ps hl _ rest
    rw [List.eq_nil_of_length_eq_zero (by omega : ps.length = 0)]
    rw [Fri.rebuildSubsets.go.eq_def]; rfl
  | succ n ih =>
    intro ps hl hs rest
    match ps, hl, hs with
    | [], _, _ => rw [Fri.rebuildSubsets.go.eq_def]; rfl
    | [p], _, _ =>
      rcases Nat.mod_two_eq_zero_or_one p with h0 | h1
      · show Fri.rebuildSubsets.go [(p, Cv qs p)]
          ((if p % 2 = 0 then C1 qs (p / 2) else C0 qs (p / 2)) :: rest) = _
        rw [if_pos h0, Fri.rebuildSubsets.go.eq_def]
        dsimp only
        rw [if_pos h0, cv_even qs h0]
        rfl
      · show Fri.rebuildSubsets.go [(p, Cv qs p)]
          ((if p % 2 = 0 then C1 qs (p / 2) else C0 qs (p / 2)) :: rest) = _
        rw [if_neg (by omega), Fri.rebuildSubsets.go.eq_def]
        dsimp only
        rw [if_neg (show ¬ p % 2 = 0 by omega), cv_odd qs h1, Fri.rebuildSubsets.go.eq_1]
        rfl
    | p :: p' :: rs, hl, hs =>
      have hs' := List.pairwise_cons.mp hs
      have hlt : p < p' := hs'.1 p' List.mem_cons_self
      by_cases hm : p % 2 = 0 ∧ p' = p + 1
      · obtain ⟨h0, rfl⟩ := hm
        have hrest : rs.Pairwise (· < ·) := (List.pairwise_cons.mp hs'.2).2
        have ihr := ih rs (by simp at hl; omega) hrest rest
        have hw : fwit qs (p :: (p + 1) :: rs) = fwit qs rs := by
          show (if p % 2 = 0 ∧ p + 1 = p + 1 then fwit qs rs else _) = _
          rw [if_pos ⟨h0, rfl⟩]
        have hp : par (p :: (p + 1) :: rs) = p / 2 :: par rs := by
          show (if p ^^^ 1 = p + 1 then p / 2 :: par rs else p / 2 :: par ((p + 1) :: rs)) = _
          rw [if_pos ((merge_iff hlt).mpr ⟨h0, rfl⟩)]
        rw [hw, hp]
        show Fri.rebuildSubsets.go ((p, Cv qs p) :: (p + 1, Cv qs (p + 1)) ::
          rs.map fun p => (p, Cv qs p)) (fwit qs rs ++ rest) = _
        rw [Fri.rebuildSubsets.go.eq_def]
        dsimp only
        rw [if_pos h0, if_pos rfl, ihr]
        rw [cv_even qs h0, cv_odd qs (by omega), show (p + 1) / 2 = p / 2 by omega]
        rfl
      · have ihr := ih (p' :: rs) (by simp at hl ⊢; omega) hs'.2 rest
        have hw : fwit qs (p :: p' :: rs)
            = (if p % 2 = 0 then C1 qs (p / 2) else C0 qs (p / 2)) :: fwit qs (p' :: rs) := by
          show (if p % 2 = 0 ∧ p' = p + 1 then fwit qs rs else _) = _
          rw [if_neg hm]
        have hp : par (p :: p' :: rs) = p / 2 :: par (p' :: rs) := by
          show (if p ^^^ 1 = p' then p / 2 :: par rs else p / 2 :: par (p' :: rs)) = _
          rw [if_neg (fun h => hm ((merge_iff hlt).mp h))]
        rw [hw, hp]
        show Fri.rebuildSubsets.go ((p, Cv qs p) :: (p', Cv qs p') ::
          rs.map fun p => (p, Cv qs p)) (_ :: (fwit qs (p' :: rs) ++ rest)) = _
        rcases Nat.mod_two_eq_zero_or_one p with h0 | h1
        · have hne : p' ≠ p + 1 := fun he => hm ⟨h0, he⟩
          rw [if_pos h0, Fri.rebuildSubsets.go.eq_def]
          dsimp only
          rw [if_pos h0, if_neg hne, show ((p', Cv qs p') :: rs.map fun p => (p, Cv qs p))
            = (p' :: rs).map (fun p => (p, Cv qs p)) from rfl, ihr, cv_even qs h0]
          rfl
        · rw [if_neg (by omega)]
          simp only [Fri.rebuildSubsets.go, if_neg (show ¬ p % 2 = 0 by omega)]
          rw [show ((p', Cv qs p') :: rs.map fun p => (p, Cv qs p))
            = (p' :: rs).map (fun p => (p, Cv qs p)) from rfl, ihr, cv_odd qs h1]
          rfl

theorem zip_map_self {α β : Type} (f : α → β) :
    ∀ l : List α, l.zip (l.map f) = l.map fun a => (a, f a)
  | [] => rfl
  | a :: l => by simp [zip_map_self f l]

theorem rebuild_ok (qs : List FQ) {ps : List ℕ} (hs : ps.Pairwise (· < ·)) :
    Fri.rebuildSubsets ps (ps.map (Cv qs)) (fwit qs ps) = .ok (subsOf qs (par ps)) := by
  unfold Fri.rebuildSubsets
  rw [if_neg (by simp), zip_map_self]
  have := go_ok qs ps.length ps le_rfl hs []
  rw [List.append_nil] at this
  simp only [this]
  rfl

/-! ### The layer Merkle check -/

theorem flat_positions (qs : List FQ) :
    ∀ ks : List ℕ, ((subsOf qs ks).map fun sub => [sub.start, sub.start + 1]).flatten
      = ks.flatMap fun k => [k * 2, k * 2 + 1]
  | [] => rfl
  | k :: ks => by
    have ih := flat_positions qs ks
    simp only [subsOf, List.map_cons, List.flatten_cons, List.flatMap_cons] at ih ⊢
    rw [ih]

theorem flat_values (qs : List FQ) :
    ∀ ks : List ℕ, ((subsOf qs ks).map fun sub => sub.evals).flatten
      = (ks.flatMap fun k => [k * 2, k * 2 + 1]).map (Cv qs)
  | [] => rfl
  | k :: ks => by
    have ih := flat_values qs ks
    simp only [subsOf, List.map_cons, List.flatten_cons, List.flatMap_cons,
      List.map_append] at ih ⊢
    rw [ih, cv_even qs (show k * 2 % 2 = 0 by omega), cv_odd qs (show (k * 2 + 1) % 2 = 1 by omega),
      show k * 2 / 2 = k by omega, show (k * 2 + 1) / 2 = k by omega]
    rfl

theorem flat_sorted {ks : List ℕ} (hs : ks.Pairwise (· < ·)) :
    (ks.flatMap fun k => [k * 2, k * 2 + 1]).Pairwise (· < ·) := by
  rw [List.pairwise_flatMap]
  refine ⟨fun k _ => by simp, ?_⟩
  refine hs.imp fun {a b} hab => ?_
  intro x hx y hy
  simp only [List.mem_cons, List.not_mem_nil, or_false] at hx hy
  rcases hx with rfl | rfl <;> rcases hy with rfl | rfl <;> omega

theorem columnOrder_const (h : ℕ) (n : ℕ) :
    columnOrder (List.replicate n h) = List.range n := by
  unfold columnOrder
  rw [List.length_replicate]
  refine List.mergeSort_of_pairwise ?_
  refine List.Pairwise.imp_of_mem ?_ List.pairwise_lt_range
  intro a b ha hb _
  rw [List.getD_eq_getElem?_getD, List.getElem?_replicate,
    if_pos (List.mem_range.mp ha), List.getD_eq_getElem?_getD,
    List.getElem?_replicate, if_pos (List.mem_range.mp hb)]
  simp

theorem coords_range (v : QM31) :
    (List.range 4).map (fun c => v.coords.getD c 0) = v.coords := rfl

section
variable {qs : List FQ} {h : ℕ} {root : Bytes}

set_option maxHeartbeats 800000 in
/-- **The layer's batched Merkle check accepts** on the rebuilt subsets. -/
theorem layerMerkle_ok (hP : Paths (allMQ qs) h root) (hL : LeafInj qs)
    {ps : List ℕ} (hs : ps.Pairwise (· < ·)) (hne : ps ≠ [])
    (hmem : ∀ p ∈ ps, ∃ q ∈ qs, q.pos = p) :
    Fri.verifyLayerMerkle (subsOf qs (par ps)) h root
      (wits (allMQ qs) ((par ps).flatMap fun k => [k * 2, k * 2 + 1]) 0 h) = .ok () := by
  set ks := par ps with hks
  set uF := ks.flatMap fun k => [k * 2, k * 2 + 1] with huF
  have hkss : ks.Pairwise (· < ·) := par_sorted _ _ le_rfl hs
  have hks_mem : ∀ k ∈ ks, ∃ q ∈ qs, q.pos / 2 = k := by
    intro k hk
    obtain ⟨p, hp, rfl⟩ := mem_par'.mp hk
    obtain ⟨q, hq, rfl⟩ := hmem p hp
    exact ⟨q, hq, rfl⟩
  have huFne : uF ≠ [] := by
    obtain ⟨p, hp⟩ := List.exists_mem_of_ne_nil ps hne
    have hk : p / 2 ∈ ks := mem_par'.mpr ⟨p, hp, rfl⟩
    intro he
    have : p / 2 * 2 ∈ uF := List.mem_flatMap.mpr ⟨p / 2, hk, List.mem_cons_self⟩
    rw [he] at this
    exact List.not_mem_nil this
  unfold Fri.verifyLayerMerkle
  rw [flat_positions, flat_values]
  set columns := (List.range 4).map fun c => (uF.map (Cv qs)).map fun v => v.coords.getD c 0
    with hcolumns
  have hver : Merkle.verify root (List.replicate 4 h) h uF columns
      (wits (allMQ qs) uF 0 h) = .ok () := by
    refine verify_paths hP (flat_sorted hkss) huFne ?_ _ _ (by simp [hcolumns]) ?_ ?_
    · intro p hp
      obtain ⟨k, hk, hpk⟩ := List.mem_flatMap.mp hp
      obtain ⟨q, hq, rfl⟩ := hks_mem k hk
      simp only [List.mem_cons, List.not_mem_nil, or_false] at hpk
      rcases hpk with rfl | rfl
      · exact ⟨_, mq0_mem hq, rfl⟩
      · exact ⟨_, mq1_mem hq, rfl⟩
    · intro col hc
      rw [hcolumns] at hc
      obtain ⟨c, -, rfl⟩ := List.mem_map.mp hc
      rw [List.length_map, List.length_map]
    · intro k' hk' mq hmq hpos
      rw [columnOrder_const]
      have hcol : ∀ ci, ci < 4 → (columns.getD ci []).getD k' 0
          = (Cv qs (uF.getD k' 0)).coords.getD ci 0 := by
        intro ci hci
        have hk'' : k' < uF.length := hk'
        simp [hcolumns, List.getD_eq_getElem?_getD, hci, List.getElem?_eq_getElem hk'']
      rw [show ((List.range 4).map fun ci => (columns.getD ci []).getD k' 0)
          = (List.range 4).map (fun ci => (Cv qs (uF.getD k' 0)).coords.getD ci 0) from
        List.map_congr_left fun ci hci => hcol ci (List.mem_range.mp hci),
        coords_range, ← hpos]
      obtain ⟨q, hq, hm⟩ := List.mem_flatMap.mp hmq
      obtain ⟨e0, e1⟩ := C_of_mem hP hL hq (rfl : q.pos / 2 = q.pos / 2)
      simp only [FQ.mqs, List.mem_cons, List.not_mem_nil, or_false] at hm
      rcases hm with rfl | rfl
      · show lq q.w0 = leafHash (Cv qs (q.pos / 2 * 2)).coords
        rw [cv_even qs (by omega), show q.pos / 2 * 2 / 2 = q.pos / 2 by omega, e0]
        rfl
      · show lq q.w1 = leafHash (Cv qs (q.pos / 2 * 2 + 1)).coords
        rw [cv_odd qs (by omega), show (q.pos / 2 * 2 + 1) / 2 = q.pos / 2 by omega, e1]
        rfl
  show Except.mapError _ (Merkle.verify root (List.replicate 4 h) h uF columns
    (wits (allMQ qs) uF 0 h)) = _
  rw [hver]
  rfl

/-- **The layer's folds** are the raw queries' outputs, per subset. -/
theorem fold_ok (hP : Paths (allMQ qs) h root) (hL : LeafInj qs)
    (fold : Fri.Subset → Except VError QM31)
    (hfold : ∀ q ∈ qs, fold ⟨q.pos / 2 * 2, [q.w0, q.w1]⟩ = .ok q.out) :
    ∀ ks : List ℕ, (∀ k ∈ ks, ∃ q ∈ qs, q.pos / 2 = k) →
      (subsOf qs ks).mapM fold = .ok (ks.map (O qs))
  | [], _ => rfl
  | k :: ks, hks => by
    obtain ⟨q, hq, rfl⟩ := hks k List.mem_cons_self
    obtain ⟨e0, e1⟩ := C_of_mem hP hL hq (rfl : q.pos / 2 = q.pos / 2)
    show (List.mapM fold (⟨q.pos / 2 * 2, [C0 qs (q.pos / 2), C1 qs (q.pos / 2)]⟩
      :: subsOf qs ks)) = _
    rw [List.mapM_cons, e0, e1, hfold q hq,
      fold_ok hP hL fold hfold ks fun k hk => hks k (List.mem_cons_of_mem _ hk),
      List.map_cons, O_of_mem hP hL fold hfold hq rfl]
    rfl

end

/-! ### Folded positions -/

theorem foldDedup_cons {x : ℕ} :
    ∀ {l : List ℕ}, (∀ y ∈ l.head?, y ≠ x) →
      Fri.foldPositions.dedup (x :: l) = x :: Fri.foldPositions.dedup l
  | [], _ => rfl
  | y :: l, hne => by
    have : y ≠ x := hne y rfl
    show (if x = y then _ else _) = _
    rw [if_neg (Ne.symm this)]

theorem foldPositions_par : ∀ (n : ℕ) (ps : List ℕ), ps.length ≤ n →
    ps.Pairwise (· < ·) → Fri.foldPositions.dedup (ps.map (· / 2)) = par ps := by
  intro n
  induction n with
  | zero =>
    intro ps hl _
    rw [List.eq_nil_of_length_eq_zero (by omega : ps.length = 0)]
    rfl
  | succ n ih =>
    intro ps hl hs
    match ps, hl, hs with
    | [], _, _ => rfl
    | [i], _, _ => rfl
    | i :: j :: rs, hl, hs =>
      have hs' := List.pairwise_cons.mp hs
      have hs'' := List.pairwise_cons.mp hs'.2
      have hij : i < j := hs'.1 j List.mem_cons_self
      have hhead : ∀ y ∈ (rs.map (· / 2)).head?, y ≠ j / 2 ∧ y ≠ i / 2 + 0 → True :=
        fun _ _ _ => trivial
      clear hhead
      by_cases hx : i ^^^ 1 = j
      · obtain ⟨h0, rfl⟩ := (merge_iff hij).mp hx
        have hp : par (i :: (i + 1) :: rs) = i / 2 :: par rs := by
          show (if i ^^^ 1 = i + 1 then i / 2 :: par rs else _) = _
          rw [if_pos hx]
        rw [hp]
        show Fri.foldPositions.dedup (i / 2 :: (i + 1) / 2 :: rs.map (· / 2)) = _
        rw [show (i + 1) / 2 = i / 2 by omega]
        show (if i / 2 = i / 2 then Fri.foldPositions.dedup (i / 2 :: rs.map (· / 2))
          else _) = _
        rw [if_pos rfl, foldDedup_cons, ih rs (by simp at hl; omega) hs''.2]
        intro y hy
        cases rs with
        | nil => simp at hy
        | cons k rs =>
          simp only [List.map_cons, List.head?_cons, Option.mem_def, Option.some.injEq] at hy
          have := hs''.1 k List.mem_cons_self
          omega
      · have hp : par (i :: j :: rs) = i / 2 :: par (j :: rs) := by
          show (if i ^^^ 1 = j then _ else i / 2 :: par (j :: rs)) = _
          rw [if_neg hx]
        rw [hp]
        show Fri.foldPositions.dedup (i / 2 :: (j :: rs).map (· / 2)) = _
        rw [foldDedup_cons, ih (j :: rs) (by simp at hl ⊢; omega) hs'.2]
        intro y hy
        simp only [List.map_cons, List.head?_cons, Option.mem_def, Option.some.injEq] at hy
        subst hy
        rcases Nat.even_or_odd' i with ⟨t, rfl | rfl⟩
        · rw [xor_one_even] at hx; omega
        · omega

theorem foldPositions_eq {ps : List ℕ} (hs : ps.Pairwise (· < ·)) :
    Fri.foldPositions ps = par ps :=
  foldPositions_par ps.length ps le_rfl hs

/-! ### The layer walk -/

/-- What one spec layer needs: the raw queries' Merkle and leaf facts,
their folds, membership of the incoming positions, the value link from
the previous layer's outputs, and the proof's witnesses being the
explicit ones. `psPrev` are the previous layer's positions; this
layer's positions are `par psPrev`. -/
structure LayerOK (logSize : ℕ) (fold : Fri.Subset → Except VError QM31)
    (root : Bytes) (fw : List QM31) (hw : List Bytes)
    (qsPrev qs : List FQ) (psPrev : List ℕ) : Prop where
  paths : Paths (allMQ qs) logSize root
  leaf : LeafInj qs
  fold : ∀ q ∈ qs, fold ⟨q.pos / 2 * 2, [q.w0, q.w1]⟩ = .ok q.out
  mem : ∀ p ∈ par psPrev, ∃ q ∈ qs, q.pos = p
  link : ∀ p ∈ par psPrev, O qsPrev p = Cv qs p
  fw : fw = fwit qs (par psPrev)
  hw : hw = wits (allMQ qs) ((par (par psPrev)).flatMap fun k => [k * 2, k * 2 + 1]) 0 logSize

/-- The inner layers, each `LayerOK` against its predecessor; the last
argument is the final layer's raw queries. -/
inductive InnerOK : List (LineDomain × QM31 × Fri.FriLayerProof) → List FQ → List ℕ →
    List FQ → Prop
  | nil (qsPrev : List FQ) (psPrev : List ℕ) : InnerOK [] qsPrev psPrev qsPrev
  | cons (d : LineDomain) (a : QM31) (pr : Fri.FriLayerProof)
      (rest : List (LineDomain × QM31 × Fri.FriLayerProof))
      (qsPrev qs qsLast : List FQ) (psPrev : List ℕ) :
      LayerOK d.logSize (Fri.foldLineSubset d a) pr.commitment pr.friWitness pr.hashWitness
        qsPrev qs psPrev →
      InnerOK rest qs (par psPrev) qsLast →
      InnerOK ((d, a, pr) :: rest) qsPrev psPrev qsLast

theorem mapError_ok {α : Type} {f : VError → VError} {x : α} :
    (Except.ok x : Except VError α).mapError f = .ok x := rfl

set_option maxHeartbeats 800000 in
/-- **The inner decommit walk succeeds**, ending at positions whose
values are the final layer's raw outputs. -/
theorem decommitInner_ok :
    ∀ (layers : List (LineDomain × QM31 × Fri.FriLayerProof)) (qsPrev : List FQ)
      (psPrev : List ℕ) (qsLast : List FQ),
      InnerOK layers qsPrev psPrev qsLast →
      psPrev.Pairwise (· < ·) → psPrev ≠ [] →
      (∀ p ∈ psPrev, ∃ q ∈ qsPrev, q.pos = p) →
      ∃ fps, Fri.decommitInner layers (par psPrev) ((par psPrev).map (O qsPrev))
          = .ok (par fps, (par fps).map (O qsLast)) ∧
        fps.Pairwise (· < ·) ∧ fps ≠ [] ∧ (∀ p ∈ fps, ∃ q ∈ qsLast, q.pos = p) := by
  intro layers qsPrev psPrev qsLast hI
  induction hI with
  | nil qsPrev psPrev =>
    intro hs hne hmem
    exact ⟨psPrev, rfl, hs, hne, hmem⟩
  | cons d a pr rest qsPrev qs qsLast psPrev hL _ ih =>
    intro hs hne hmem
    have hps : (par psPrev).Pairwise (· < ·) := par_sorted _ _ le_rfl hs
    have hpne : par psPrev ≠ [] := by
      obtain ⟨p, hp⟩ := List.exists_mem_of_ne_nil psPrev hne
      intro he
      have : p / 2 ∈ par psPrev := mem_par'.mpr ⟨p, hp, rfl⟩
      rw [he] at this
      exact List.not_mem_nil this
    have hev : (par psPrev).map (O qsPrev) = (par psPrev).map (Cv qs) :=
      List.map_congr_left hL.link
    have hkmem : ∀ k ∈ par (par psPrev), ∃ q ∈ qs, q.pos / 2 = k := by
      intro k hk
      obtain ⟨p, hp, rfl⟩ := mem_par'.mp hk
      obtain ⟨q, hq, rfl⟩ := hL.mem p hp
      exact ⟨q, hq, rfl⟩
    obtain ⟨fps, hrec, hfs, hfne, hfmem⟩ := ih hps hpne hL.mem
    refine ⟨fps, ?_, hfs, hfne, hfmem⟩
    show (do
      let subs ← (Fri.rebuildSubsets (par psPrev) ((par psPrev).map (O qsPrev))
        pr.friWitness).mapError fun (e : VError) => match e with
          | VError.insufficientWitness | VError.shapeMismatch => VError.innerLayerEvaluationsInvalid
          | e => e
      (Fri.verifyLayerMerkle subs d.logSize pr.commitment pr.hashWitness).mapError
        fun _ => VError.innerLayerCommitmentInvalid
      let evals' ← subs.mapM (Fri.foldLineSubset d a)
      Fri.decommitInner rest (Fri.foldPositions (par psPrev)) evals') = _
    rw [hev, hL.fw, rebuild_ok qs hps, mapError_ok]
    dsimp only [bind, Except.bind]
    rw [hL.hw, layerMerkle_ok hL.paths hL.leaf hps hpne hL.mem]
    dsimp only [bind, Except.bind, Except.mapError]
    rw [fold_ok hL.paths hL.leaf _ hL.fold _ hkmem]
    dsimp only [bind, Except.bind]
    rw [foldPositions_eq hps]
    exact hrec

theorem O_mem_out {qs : List FQ} {k : ℕ} (h : ∃ q ∈ qs, q.pos / 2 = k) :
    ∃ q ∈ qs, O qs k = q.out := by
  obtain ⟨q, hq, hk⟩ := h
  obtain ⟨q₁, hq₁, -, hf⟩ := find_coset hq hk
  exact ⟨q₁, hq₁, by unfold O; rw [hf]⟩

set_option maxHeartbeats 800000 in
/-- **The spec's FRI decommitment accepts** on the sorted unique first-layer
positions, given the per-raw-query layer facts: the first (circle) layer's
Merkle/leaf/fold facts and explicit witnesses, `InnerOK` for the inner
layers, and every final raw output equal to the last-layer constant. -/
theorem decommit_ok (c : Fri.Committed) {qs0 qsLast : List FQ} {uniq : List ℕ}
    {c0 : QM31} (hs : uniq.Pairwise (· < ·)) (hne : uniq ≠ [])
    (hmem : ∀ p ∈ uniq, ∃ q ∈ qs0, q.pos = p)
    (hP : Paths (allMQ qs0) c.columnCommitmentDomain.logSize c.firstProof.commitment)
    (hL : LeafInj qs0)
    (hfold : ∀ q ∈ qs0, Fri.foldCircleSubset c.columnCommitmentDomain c.firstAlpha
      ⟨q.pos / 2 * 2, [q.w0, q.w1]⟩ = .ok q.out)
    (hfw : c.firstProof.friWitness = fwit qs0 uniq)
    (hhw : c.firstProof.hashWitness = wits (allMQ qs0)
      ((par uniq).flatMap fun k => [k * 2, k * 2 + 1]) 0 c.columnCommitmentDomain.logSize)
    (hI : InnerOK c.innerLayers qs0 uniq qsLast)
    (hpoly : c.lastLayerPoly = [c0]) (hlast : ∀ q ∈ qsLast, q.out = c0) :
    Fri.decommit c uniq (uniq.map (Cv qs0)) = .ok () := by
  have hkmem : ∀ k ∈ par uniq, ∃ q ∈ qs0, q.pos / 2 = k := by
    intro k hk
    obtain ⟨p, hp, rfl⟩ := mem_par'.mp hk
    obtain ⟨q, hq, rfl⟩ := hmem p hp
    exact ⟨q, hq, rfl⟩
  obtain ⟨fps, hrec, -, -, hfmem⟩ := decommitInner_ok _ _ _ _ hI hs hne hmem
  unfold Fri.decommit
  rw [hfw, rebuild_ok qs0 hs, mapError_ok]
  dsimp only [bind, Except.bind]
  rw [hhw, layerMerkle_ok hP hL hs hne hmem]
  dsimp only [bind, Except.bind, Except.mapError]
  rw [fold_ok hP hL _ hfold _ hkmem]
  dsimp only [bind, Except.bind]
  rw [foldPositions_eq hs, hrec]
  dsimp only [bind, Except.bind]
  rw [SpecLemmas.lastLayerCheck_const c c0 hpoly _ _ (by rw [List.length_map])]
  intro e he
  obtain ⟨k, hk, rfl⟩ := List.mem_map.mp he
  obtain ⟨p, hp, rfl⟩ := mem_par'.mp hk
  obtain ⟨q, hq, rfl⟩ := hfmem p hp
  obtain ⟨q₁, hq₁, ho⟩ := O_mem_out ⟨q, hq, rfl⟩
  rw [ho, hlast q₁ hq₁]

end StwoVerifier.FriBatch
