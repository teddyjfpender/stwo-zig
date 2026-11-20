/-
**The spec's column order is lexicographic on `(log size, index)`.**

`Merkle.columnOrder` stably merge-sorts the column indices by log size.
Stability (core's `mergeSort_zipIdx`) makes the order strictly
increasing in `(log, index)`, which is the order the in-circuit query
sorter enforces with its keys `log · 2^b + index`.
-/
import StwoVerifier.Merkle

namespace StwoVerifier.ColumnOrder

open StwoVerifier Merkle

/-- Strict lexicographic order on `(log, index)`. -/
def Lex (logs : List ℕ) (i j : ℕ) : Prop :=
  logs.getD i 0 < logs.getD j 0 ∨ (logs.getD i 0 = logs.getD j 0 ∧ i < j)

theorem zipIdx_range_mem {n : ℕ} {z : ℕ × ℕ} (h : z ∈ (List.range n).zipIdx) :
    z.1 = z.2 ∧ z.1 < n := by
  obtain ⟨k, hk, rfl⟩ := List.getElem_of_mem h
  simp only [List.length_zipIdx, List.length_range] at hk
  simp [List.getElem_zipIdx, hk]

theorem columnOrder_perm (logs : List ℕ) :
    (columnOrder logs).Perm (List.range logs.length) := List.mergeSort_perm _ _

theorem columnOrder_nodup (logs : List ℕ) : (columnOrder logs).Nodup :=
  (columnOrder_perm logs).nodup_iff.mpr List.nodup_range

/-- **Stability**: the spec's column order is strictly increasing in
`(log, index)`. -/
theorem columnOrder_lex (logs : List ℕ) : (columnOrder logs).Pairwise (Lex logs) := by
  set le : ℕ → ℕ → Bool := fun i j => decide (logs.getD i 0 ≤ logs.getD j 0) with hle
  have htrans : ∀ a b c : ℕ, le a b → le b c → le a c := by
    intro a b c h1 h2; simp only [hle, decide_eq_true_eq] at *; omega
  have htotal : ∀ a b : ℕ, (le a b || le b a) = true := by
    intro a b; simp only [hle, Bool.or_eq_true, decide_eq_true_eq]; omega
  have hz := List.mergeSort_zipIdx (le := le) (l := List.range logs.length)
  have hcol : columnOrder logs = List.mergeSort (List.range logs.length) le := rfl
  set Z := List.mergeSort ((List.range logs.length).zipIdx) (List.zipIdxLE le) with hZ
  have hpw : Z.Pairwise (fun a b => List.zipIdxLE le a b = true) :=
    List.pairwise_mergeSort (List.zipIdxLE_trans htrans) (List.zipIdxLE_total htotal) _
  have hmem : ∀ z ∈ Z, z.1 = z.2 := fun z hz' =>
    (zipIdx_range_mem (List.mem_mergeSort.mp hz')).1
  have hnd : (Z.map (·.1)).Nodup := by
    rw [hz, ← hcol]; exact columnOrder_nodup logs
  rw [hcol, ← hz, List.pairwise_map]
  have hpw' : Z.Pairwise (fun a b => List.zipIdxLE le a b = true ∧ a.1 ≠ b.1) := by
    have := (List.pairwise_map.mp hnd)
    exact List.Pairwise.and hpw this
  refine hpw'.imp_of_mem fun {a b} ha hb ⟨hab, hne⟩ => ?_
  have ha' := hmem a ha
  have hb' := hmem b hb
  unfold List.zipIdxLE at hab
  unfold Lex
  simp only [hle] at hab
  split at hab
  · rename_i h1
    split at hab
    · rename_i h2
      simp only [decide_eq_true_eq] at h1 h2 hab
      right; refine ⟨by omega, ?_⟩
      rw [ha', hb']; rw [ha', hb'] at hne; omega
    · rename_i h2
      simp only [decide_eq_true_eq] at h1 h2
      left; omega
  · exact absurd hab Bool.false_ne_true

/-- **Uniqueness**: a `Lex`-sorted permutation of the indices is the
column order. -/
theorem columnOrder_unique {logs l : List ℕ} (hp : l.Perm (List.range logs.length))
    (hl : l.Pairwise (Lex logs)) : l = columnOrder logs := by
  refine hp.trans (columnOrder_perm logs).symm |>.eq_of_pairwise ?_ hl (columnOrder_lex logs)
  intro a _ b _ h1 h2
  unfold Lex at h1 h2
  omega

/-- The column order only compares log sizes: a uniform shift keeps it. -/
theorem columnOrder_shift (logs : List ℕ) (b : ℕ) :
    columnOrder (logs.map (· + b)) = columnOrder logs := by
  symm
  refine columnOrder_unique (by rw [List.length_map]; exact columnOrder_perm logs) ?_
  refine (columnOrder_lex logs).imp_of_mem fun {i j} hi hj h => ?_
  have hi' : i < logs.length := List.mem_range.mp ((columnOrder_perm logs).mem_iff.mp hi)
  have hj' : j < logs.length := List.mem_range.mp ((columnOrder_perm logs).mem_iff.mp hj)
  unfold Lex at h ⊢
  rw [List.getD_eq_getElem?_getD, List.getElem?_map, List.getElem?_eq_getElem hi',
    List.getD_eq_getElem?_getD, List.getElem?_map, List.getElem?_eq_getElem hj']
  rw [List.getD_eq_getElem?_getD, List.getElem?_eq_getElem hi',
    List.getD_eq_getElem?_getD, List.getElem?_eq_getElem hj'] at h
  simp only [Option.map_some, Option.getD_some] at h ⊢
  omega

/-- Nondecreasing log sizes: the column order is the identity. -/
theorem columnOrder_mono {logs : List ℕ}
    (hm : ∀ i j, i < j → j < logs.length → logs.getD i 0 ≤ logs.getD j 0) :
    columnOrder logs = List.range logs.length := by
  symm
  refine columnOrder_unique (List.Perm.refl _) ?_
  rw [List.pairwise_iff_getElem]
  intro i j hi hj hij
  simp only [List.getElem_range]
  unfold Lex
  have := hm i j hij (by simpa using hj)
  omega

end StwoVerifier.ColumnOrder
