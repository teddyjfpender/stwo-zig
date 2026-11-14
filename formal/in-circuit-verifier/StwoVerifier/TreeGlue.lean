/-
**One eval-domain tree, end to end**: per raw query, the root is the
path root of the query's leaf along its position digits (what the
circuit's per-query leaf + path gadgets give); with the instance-level
collision hypothesis, the spec's batched `Merkle.verify` accepts at the
sorted unique positions, with the queried values read off
representative raw queries.
-/
import StwoVerifier.MerklePathBridge
import StwoVerifier.MerkleBatch
import StwoVerifier.ColumnOrder

namespace StwoVerifier.TreeGlue

open StwoVerifier StwoVerifier.Gadgets MerkleBatch Merkle

theorem grm {β : Type} (f : ℕ → β) (d : β) {m i : ℕ} (hi : i < m) :
    ((List.range m).map f).getD i d = f i := by
  rw [List.getD_eq_getElem?_getD, List.getElem?_map, List.getElem?_range hi]; rfl

/-! ### Sorted unique positions -/

theorem dedup_mem : ∀ {l : List ℕ} {x : ℕ}, x ∈ sortedUnique.dedup l ↔ x ∈ l
  | [], _ => Iff.rfl
  | [_], _ => Iff.rfl
  | a :: b :: rest, x => by
    show x ∈ (if a = b then sortedUnique.dedup (b :: rest) else a :: sortedUnique.dedup (b :: rest)) ↔ _
    by_cases hab : a = b
    · rw [if_pos hab, dedup_mem, hab]
      simp
    · rw [if_neg hab, List.mem_cons, dedup_mem]
      exact List.mem_cons.symm

theorem dedup_sorted : ∀ {l : List ℕ}, l.Pairwise (· ≤ ·) → (sortedUnique.dedup l).Pairwise (· < ·)
  | [], _ => List.Pairwise.nil
  | [_], _ => List.pairwise_singleton _ _
  | a :: b :: rest, h => by
    show (if a = b then sortedUnique.dedup (b :: rest) else a :: sortedUnique.dedup (b :: rest)).Pairwise _
    have ht := (List.pairwise_cons.mp h).2
    by_cases hab : a = b
    · rw [if_pos hab]; exact dedup_sorted ht
    · rw [if_neg hab]
      refine List.pairwise_cons.mpr ⟨fun z hz => ?_, dedup_sorted ht⟩
      have hab' : a ≤ b := (List.pairwise_cons.mp h).1 b List.mem_cons_self
      rcases List.mem_cons.mp (dedup_mem.mp hz) with rfl | hz'
      · omega
      · have := (List.pairwise_cons.mp ht).1 z hz'
        omega

theorem sortedUnique_mem {l : List ℕ} {x : ℕ} : x ∈ sortedUnique l ↔ x ∈ l := by
  unfold sortedUnique
  rw [dedup_mem, List.mem_mergeSort]

theorem sortedUnique_lt (l : List ℕ) : (sortedUnique l).Pairwise (· < ·) := by
  unfold sortedUnique
  refine dedup_sorted ?_
  have := List.pairwise_mergeSort (le := fun a b : ℕ => decide (a ≤ b))
    (fun a b c h1 h2 => by simp only [decide_eq_true_eq] at *; omega)
    (fun a b => by simp only [Bool.or_eq_true, decide_eq_true_eq]; omega) l
  exact this.imp fun h => by simpa using h

/-- A representative raw query of a unique position. -/
def rep (raw uniq : List ℕ) (k : ℕ) : ℕ := raw.findIdx (· = uniq.getD k 0)

theorem rep_spec {raw : List ℕ} {k : ℕ} (hk : k < (sortedUnique raw).length) :
    rep raw (sortedUnique raw) k < raw.length ∧
    raw.getD (rep raw (sortedUnique raw) k) 0 = (sortedUnique raw).getD k 0 := by
  have hmem : (sortedUnique raw).getD k 0 ∈ raw := by
    rw [← sortedUnique_mem, List.getD_eq_getElem _ _ hk]
    exact List.getElem_mem _
  have hex : ∃ x ∈ raw, decide (x = (sortedUnique raw).getD k 0) = true :=
    ⟨_, hmem, by simp⟩
  have hlt := List.findIdx_lt_length_of_exists hex
  refine ⟨hlt, ?_⟩
  have := List.findIdx_getElem (w := hlt)
  unfold rep
  rw [List.getD_eq_getElem _ _ hlt]
  simpa using this

/-! ### The tree -/

/-- The raw queries' Merkle views. -/
def mqsOf (nq : ℕ) (raw : List ℕ) (leaf : ℕ → Channel.Bytes) (authB : ℕ → List Channel.Bytes) : List MQ :=
  (List.range nq).map fun q => ⟨raw.getD q 0, leaf q, authB q⟩

theorem mem_mqsOf {nq : ℕ} {raw : List ℕ} {leaf : ℕ → Channel.Bytes} {authB : ℕ → List Channel.Bytes} {m : MQ}
    (h : m ∈ mqsOf nq raw leaf authB) : ∃ q, q < nq ∧ m = ⟨raw.getD q 0, leaf q, authB q⟩ := by
  obtain ⟨q, hq, rfl⟩ := List.mem_map.mp h
  exact ⟨q, List.mem_range.mp hq, rfl⟩

theorem tree_paths {nq L : ℕ} {raw : List ℕ} {leaf : ℕ → Channel.Bytes} {authB : ℕ → List Channel.Bytes}
    {root : Channel.Bytes}
    (hlt : ∀ q, q < nq → raw.getD q 0 < 2 ^ L)
    (hpath : ∀ q, q < nq →
      root = pathRoot (leaf q) ((List.range L).map fun t => raw.getD q 0 / 2 ^ t % 2) (authB q))
    (hleaf : ∀ q, q < nq → (leaf q).length = 32)
    (hal : ∀ q, q < nq → (authB q).length = L)
    (ha32 : ∀ q, q < nq → ∀ k, k < L → ((authB q).getD k []).length = 32)
    (hinj : ∀ m ∈ mqsOf nq raw leaf authB, ∀ m' ∈ mqsOf nq raw leaf authB, ∀ k, k < L →
      Blake2s.blake2s (msg m k) = Blake2s.blake2s (msg m' k) → msg m k = msg m' k) :
    Paths (mqsOf nq raw leaf authB) L root := by
  refine ⟨fun m hm => ?_, fun m hm => ?_, fun m hm => ?_, fun m hm k hk => ?_, hinj⟩
  · obtain ⟨q, hq, rfl⟩ := mem_mqsOf hm; exact hlt q hq
  · obtain ⟨q, hq, rfl⟩ := mem_mqsOf hm
    have := pathRoot_nodeAt ⟨raw.getD q 0, leaf q, authB q⟩ L 0 (by simp [hal q hq])
    simp only [List.drop_zero, Nat.zero_add] at this
    rw [List.take_of_length_le (by rw [hal q hq])] at this
    rw [← this, hpath q hq]
    rfl
  · obtain ⟨q, hq, rfl⟩ := mem_mqsOf hm; exact hleaf q hq
  · obtain ⟨q, hq, rfl⟩ := mem_mqsOf hm; exact ha32 q hq k hk

/-- **The tree's batched Merkle verification accepts.** -/
theorem tree_verify {nq L : ℕ} {raw : List ℕ} {authB : ℕ → List Channel.Bytes} {root : Channel.Bytes}
    (logs : List ℕ) (x : ℕ → ℕ → F) (hraw : raw.length = nq) (hnq : 0 < nq)
    (hP : Paths (mqsOf nq raw (fun q => leafHash ((columnOrder logs).map fun c => x c q)) authB)
      L root) :
    Merkle.verify root logs L (sortedUnique raw)
      ((List.range logs.length).map fun c =>
        (List.range (sortedUnique raw).length).map fun k => x c (rep raw (sortedUnique raw) k))
      (wits (mqsOf nq raw (fun q => leafHash ((columnOrder logs).map fun c => x c q)) authB)
        (sortedUnique raw) 0 L) = .ok () := by
  have hne : sortedUnique raw ≠ [] := by
    intro he
    have : raw.getD 0 0 ∈ sortedUnique raw := by
      rw [sortedUnique_mem, List.getD_eq_getElem _ _ (by omega)]
      exact List.getElem_mem _
    rw [he] at this; simp at this
  refine verify_paths hP (sortedUnique_lt raw) hne (fun p hp => ?_) logs _ (by simp)
    (fun col hc => ?_) (fun k hk m hm hpos => ?_)
  · obtain ⟨i, hi, rfl⟩ := List.getElem_of_mem (sortedUnique_mem.mp hp)
    exact ⟨_, List.mem_map.mpr ⟨i, List.mem_range.mpr (by omega), rfl⟩,
      by show raw.getD i 0 = _; rw [List.getD_eq_getElem _ _ hi]⟩
  · obtain ⟨c, -, rfl⟩ := List.mem_map.mp hc
    simp
  · obtain ⟨q, hq, rfl⟩ := mem_mqsOf hm
    obtain ⟨hr, he⟩ := rep_spec hk
    -- The representative query sits at the same position: same leaf.
    have hc := consist' hP (Nat.zero_le L) (q := ⟨raw.getD q 0, _, authB q⟩)
      (q' := ⟨raw.getD (rep raw (sortedUnique raw) k) 0, _, authB (rep raw (sortedUnique raw) k)⟩)
      (List.mem_map.mpr ⟨q, List.mem_range.mpr hq, rfl⟩)
      (List.mem_map.mpr ⟨_, List.mem_range.mpr (by omega), rfl⟩)
      (by simp only [pow_zero, Nat.div_one]; rw [he]; exact hpos)
    simp only [nodeAt] at hc
    rw [hc]
    show leafHash _ = leafHash _
    congr 1
    refine List.map_congr_left fun c hc' => ?_
    have hcl : c < logs.length :=
      List.mem_range.mp ((ColumnOrder.columnOrder_perm logs).mem_iff.mp hc')
    rw [grm _ _ hcl, grm _ _ hk]

end StwoVerifier.TreeGlue
