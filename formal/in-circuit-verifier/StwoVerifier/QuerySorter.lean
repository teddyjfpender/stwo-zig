/-
**The in-circuit query sorter** (`stark_verifier/sort_queries.zig`).

Each column's key is `u · (log · 2^b + index)`; a query's values are
tagged `value + key`, permuted by one permutation gate, split back into
the low (base) part and the key part. The first query of a tree checks
consecutive key differences into `[0, 2^(5+b))`; later queries require
their keys equal to the first's.

`sortFirst_sound` / `sortLater_sound`: the sorted values are the
query's values in the spec's `Merkle.columnOrder` — the distinct keys
pin the permutation (a key-sorted permutation of distinct keys is
unique, `List.Perm.eq_of_pairwise`), and the spec's stable sort is
exactly the key order (`ColumnOrder.columnOrder_lex`).
-/
import StwoVerifier.RelationUses
import StwoVerifier.ColumnOrder

namespace StwoVerifier.Gadgets

open Merkle

open StwoVerifier StwoVerifier.Gates

/-- The `u` constant `(0, 0, 1, 0)`. -/
def uQ : QM31 := QM31.fromM31s 0 0 1 0

/-- A tagged value: base `x`, key `K` on the `u` coordinate. -/
def tq (x K : F) : QM31 := ⟨⟨x, 0⟩, ⟨K, 0⟩⟩

theorem uQ_mul_base (K : F) : uQ * QM31.fromBase K = ⟨⟨0, 0⟩, ⟨K, 0⟩⟩ := by
  rw [mul_comm, mul_base_eq]
  simp [uQ, QM31.fromM31s]

theorem tag_eq (x K : F) : QM31.fromBase x + uQ * QM31.fromBase K = tq x K := by
  rw [uQ_mul_base]
  simp [tq, QM31.fromBase, CM31.fromBase]
  refine QM31.ext' ?_ ?_ <;> (ext <;> simp)

theorem low_eq (x K : F) : pmulQ (tq x K) 1 = QM31.fromBase x := by
  refine QM31.ext' ?_ ?_ <;> (ext <;> simp [pmulQ, tq, QM31.fromBase, CM31.fromBase] <;> rfl)

theorem key_eq (x K : F) : tq x K - QM31.fromBase x = uQ * QM31.fromBase K := by
  rw [uQ_mul_base]
  refine QM31.ext' ?_ ?_ <;> (ext <;> simp [tq, QM31.fromBase, CM31.fromBase])

theorem uQ_ne_zero : uQ ≠ 0 := by
  intro h
  have := congrArg (fun q : QM31 => q.c1.a) h
  simp [uQ, QM31.fromM31s] at this

theorem diff_eq (a b : F) :
    (uQ * QM31.fromBase a - uQ * QM31.fromBase b) * uQ⁻¹ = QM31.fromBase (a - b) := by
  rw [← mul_sub, mul_comm, ← mul_assoc, inv_mul_cancel₀ uQ_ne_zero, one_mul]
  exact (map_sub baseHom a b).symm

/-- The key coordinate. -/
def kf (q : QM31) : F := q.c1.a

theorem kf_tq (x K : F) : kf (tq x K) = K := rfl

/-! ### Keys -/

/-- `generate_sort_keys` from column `c` on. -/
def keysG (u shift : ℕ) : List ℕ → ℕ → ℕ → Out (List ℕ)
  | [], _, n => ⟨[], [], n⟩
  | l :: ls, c, n =>
    let r := keysG u shift ls (c + 1) (n + 4)
    ⟨[.mul n l shift, .const (n + 1) (QM31.fromBase ((c : ℕ) : F)), .add (n + 2) n (n + 1),
      .mul (n + 3) u (n + 2)] ++ r.ops, (n + 3) :: r.res, r.next⟩

theorem keysG_sound {ρ : ℕ → QM31} {u shift b : ℕ} (hu : ρ u = uQ)
    (hshift : ρ shift = QM31.fromBase ((2 ^ b : ℕ) : F)) (logs : ℕ → ℕ) :
    ∀ (ls : List ℕ) (c n : ℕ),
      (∀ k, k < ls.length → ρ (ls.getD k 0) = QM31.fromBase ((logs (c + k) : ℕ) : F)) →
      AllHold ρ (keysG u shift ls c n).ops →
      (keysG u shift ls c n).res.length = ls.length ∧
      ∀ k, k < ls.length → ρ ((keysG u shift ls c n).res.getD k 0)
        = uQ * QM31.fromBase (((logs (c + k) * 2 ^ b + (c + k) : ℕ) : F)) := by
  intro ls
  induction ls with
  | nil => intro c n _ _; exact ⟨rfl, fun k hk => absurd hk (by simp)⟩
  | cons l ls ih =>
    intro c n hl h
    rw [show (keysG u shift (l :: ls) c n).ops =
      [.mul n l shift, .const (n + 1) (QM31.fromBase ((c : ℕ) : F)), .add (n + 2) n (n + 1),
        .mul (n + 3) u (n + 2)] ++ (keysG u shift ls (c + 1) (n + 4)).ops from rfl,
      allHold_append] at h
    obtain ⟨h1, h2⟩ := h
    simp only [allHold_cons, Holds] at h1
    obtain ⟨hm, hc, ha, hk, -⟩ := h1
    obtain ⟨ihl, ihv⟩ := ih (c + 1) (n + 4)
      (fun k hk' => by rw [show c + 1 + k = c + (k + 1) by omega]; exact hl (k + 1) (by simp; omega))
      h2
    refine ⟨by show _ + 1 = _; rw [ihl]; rfl, fun k hk' => ?_⟩
    rcases k with _ | k
    · show ρ (n + 3) = _
      rw [hk, hu, ha, hm, hc, hshift, show l = (l :: ls).getD 0 0 from rfl, hl 0 (by simp),
        fromBase_mul']
      congr 1
      show baseHom _ + baseHom _ = baseHom _
      rw [← map_add]
      congr 1
      push_cast; ring
    · show ρ ((keysG u shift ls (c + 1) (n + 4)).res.getD k 0) = _
      rw [ihv k (by simp at hk'; omega), show c + 1 + k = c + (k + 1) by omega]

/-! ### One sort -/

/-- Tag, permute, split: lows and keys of the sorted values. -/
def sortCoreG (one : ℕ) (vals keys : List ℕ) (n : ℕ) : Out (List ℕ × List ℕ) :=
  let tag := lanewise2 .add vals keys n
  let m := tag.res.length
  let s := tag.next
  ⟨tag.ops ++ [.perm ((List.range m).map (s + ·)) tag.res] ++
    (List.range m).flatMap (fun k =>
      [.pmul (s + m + 2 * k) (s + k) one, .sub (s + m + 2 * k + 1) (s + k) (s + m + 2 * k)]),
   ((List.range m).map (fun k => s + m + 2 * k), (List.range m).map (fun k => s + m + 2 * k + 1)),
   s + 3 * m⟩

/-- The first query's order check: consecutive key differences
`(key_{k+1} − key_k)·u⁻¹`, packed, range-checked to `kb` bits. -/
def verifyFirstG (zero uinv : ℕ) (keys : List ℕ) (kb n : ℕ) : Out Unit :=
  let m := keys.length
  let dops := (List.range (m - 1)).flatMap fun k =>
    [.sub (n + 2 * k) (keys.getD (k + 1) 0) (keys.getD k 0), .mul (n + 2 * k + 1) (n + 2 * k) uinv]
  let pk := packG ((List.range (m - 1)).map fun k => n + 2 * k + 1) (n + 2 * (m - 1))
  let eb := extractBitsK zero pk.res kb pk.next
  ⟨dops ++ pk.ops ++ eb.ops, (), eb.next⟩

/-- Later queries: keys equal to the first query's. -/
def keysEqG (keys first : List ℕ) : List Op :=
  (List.range keys.length).map fun k => .eq (keys.getD k 0) (first.getD k 0)

/-! ### The sorting argument -/

/-- A small field difference of two small naturals: no wrap-around. -/
theorem sub_val_bound {a b N : ℕ} (hN : N ≤ 2 ^ 30) (ha : a < N) (hb : b < N)
    (h : (((b : ℕ) : F) - ((a : ℕ) : F)).val < N) : a ≤ b := by
  by_contra hlt
  push Not at hlt
  have hP : P = 2147483647 := rfl
  have hcast : (((b : ℕ) : F) - ((a : ℕ) : F)) = ((P - (a - b) : ℕ) : F) := by
    rw [Nat.cast_sub (by rw [hP]; omega), ZMod.natCast_self, zero_sub,
      Nat.cast_sub (le_of_lt hlt)]
    ring
  rw [hcast, ZMod.val_cast_of_lt (by rw [hP]; omega)] at h
  rw [hP] at h
  omega

/-- The spec key of column `c`. -/
def colKey (logs : List ℕ) (b c : ℕ) : ℕ := logs.getD c 0 * 2 ^ b + c

theorem colKey_lex {logs : List ℕ} {b i j : ℕ} (hi : i < 2 ^ b) (hj : j < 2 ^ b)
    (h : ColumnOrder.Lex logs i j) : colKey logs b i < colKey logs b j := by
  unfold colKey
  rcases h with h | ⟨h1, h2⟩
  · have : logs.getD i 0 * 2 ^ b + 2 ^ b ≤ logs.getD j 0 * 2 ^ b := by
      have := Nat.mul_le_mul_right (2 ^ b) (show logs.getD i 0 + 1 ≤ logs.getD j 0 from h)
      linarith
    omega
  · rw [h1]; omega

theorem colKey_inj {logs : List ℕ} {b i j : ℕ} (hi : i < 2 ^ b) (hj : j < 2 ^ b)
    (h : colKey logs b i = colKey logs b j) : i = j := by
  unfold colKey at h
  have hmi := Nat.add_mul_mod_self_right i (logs.getD i 0) (2 ^ b)
  have hmj := Nat.add_mul_mod_self_right j (logs.getD j 0) (2 ^ b)
  rw [Nat.mod_eq_of_lt hi] at hmi
  rw [Nat.mod_eq_of_lt hj] at hmj
  rw [← hmi, ← hmj, add_comm i, add_comm j, h]

theorem colKey_lt {logs : List ℕ} {b c : ℕ} (hl : logs.getD c 0 < 2 ^ 5) (hc : c < 2 ^ b) :
    colKey logs b c < 2 ^ (5 + b) := by
  unfold colKey
  rw [pow_add]
  have := Nat.mul_le_mul_right (2 ^ b) (show logs.getD c 0 + 1 ≤ 2 ^ 5 from hl)
  nlinarith

/-- **A key-sorted permutation of distinctly keyed values is the spec's
column order.** `S` is a permutation of the tagged columns whose
consecutive key differences are small; then `S` lists the columns in
`columnOrder`. -/
theorem sorted_eq_columnOrder (logs : List ℕ) (b kb : ℕ) (x : ℕ → F)
    (hkb : kb = 5 + b) (hkb30 : kb ≤ 30)
    (hm : logs.length ≤ 2 ^ b) (hlogs : ∀ c, c < logs.length → logs.getD c 0 < 2 ^ 5)
    (S : List QM31)
    (hperm : S.Perm ((List.range logs.length).map fun c =>
      tq (x c) ((colKey logs b c : ℕ) : F)))
    (hdiff : ∀ k (hk : k + 1 < S.length), (kf S[k + 1] - kf S[k]).val < 2 ^ kb) :
    S = (columnOrder logs).map fun c => tq (x c) ((colKey logs b c : ℕ) : F) := by
  set m := logs.length with hmdef
  set g : ℕ → QM31 := fun c => tq (x c) ((colKey logs b c : ℕ) : F) with hg
  have hb30 : 2 ^ kb ≤ 2 ^ 30 := Nat.pow_le_pow_right (by norm_num) hkb30
  have hkey : ∀ c, c < m → colKey logs b c < 2 ^ kb := fun c hc => by
    rw [hkb]; exact colKey_lt (hlogs c hc) (by omega)
  have hval : ∀ c, c < m → (kf (g c)).val = colKey logs b c := fun c hc => by
    rw [hg, kf_tq, ZMod.val_cast_of_lt (by have := hkey c hc; unfold P; omega)]
  have ginj : ∀ i, i < m → ∀ j, j < m → g i = g j → i = j := by
    intro i hi j hj he
    have := congrArg (fun q => (kf q).val) he
    simp only [hval i hi, hval j hj] at this
    exact colKey_inj (by omega) (by omega) this
  have hTnd : ((List.range m).map g).Nodup :=
    List.Nodup.map_on (fun i hi j hj => ginj i (List.mem_range.mp hi) j (List.mem_range.mp hj))
      List.nodup_range
  have hSnd : S.Nodup := hperm.nodup_iff.mpr hTnd
  have hmem : ∀ q ∈ S, ∃ c, c < m ∧ q = g c := by
    intro q hq
    obtain ⟨c, hc, rfl⟩ := List.mem_map.mp (hperm.mem_iff.mp hq)
    exact ⟨c, List.mem_range.mp hc, rfl⟩
  let R : QM31 → QM31 → Prop := fun a b => (kf a).val < (kf b).val
  have htrans : Trans R R R := ⟨fun h1 h2 => lt_trans h1 h2⟩
  have hchain : S.IsChain R := by
    rw [List.isChain_iff_getElem]
    intro k hk
    obtain ⟨c1, hc1, he1⟩ := hmem S[k] (List.getElem_mem _)
    obtain ⟨c2, hc2, he2⟩ := hmem S[k + 1] (List.getElem_mem _)
    have hd := hdiff k hk
    rw [he1, he2, kf_tq, kf_tq] at hd
    have hle := sub_val_bound hb30 (hkey c1 hc1) (hkey c2 hc2) hd
    have hne : c1 ≠ c2 := by
      intro hc
      rw [hc] at he1
      have := (List.Nodup.getElem_inj_iff hSnd).mp (he1.trans he2.symm)
      omega
    have hne' : colKey logs b c1 ≠ colKey logs b c2 := fun h =>
      hne (colKey_inj (by omega) (by omega) h)
    show (kf S[k]).val < (kf S[k + 1]).val
    rw [he1, he2, hval c1 hc1, hval c2 hc2]
    omega
  have hS : S.Pairwise R := List.isChain_iff_pairwise.mp hchain
  have hL : ((columnOrder logs).map g).Pairwise R := by
    rw [List.pairwise_map]
    refine (ColumnOrder.columnOrder_lex logs).imp_of_mem fun {i j} hi hj hlex => ?_
    have hi' := List.mem_range.mp ((ColumnOrder.columnOrder_perm logs).mem_iff.mp hi)
    have hj' := List.mem_range.mp ((ColumnOrder.columnOrder_perm logs).mem_iff.mp hj)
    show (kf (g i)).val < (kf (g j)).val
    rw [hval i hi', hval j hj']
    exact colKey_lex (by omega) (by omega) hlex
  have hLperm : ((columnOrder logs).map g).Perm ((List.range m).map g) :=
    (ColumnOrder.columnOrder_perm logs).map g
  exact List.Perm.eq_of_pairwise
    (fun a b _ _ h1 h2 => absurd (lt_trans h1 h2) (lt_irrefl _)) hS hL
    (hperm.trans hLperm.symm)

/-! ### Gadget-level soundness -/

theorem getD_range_map (f : ℕ → ℕ) {m k : ℕ} (hk : k < m) :
    ((List.range m).map f).getD k 0 = f k := by
  rw [List.getD_eq_getElem?_getD, List.getElem?_map, List.getElem?_range hk]; rfl

/-- What one sort gives: the permuted values are a permutation of the
tagged columns, and lows/keys split each permuted value. -/
theorem sortCore_sound {ρ : ℕ → QM31} {one : ℕ} {vals keys : List ℕ} {n : ℕ}
    (x K : ℕ → F) (hone : ρ one = 1) (hlen : vals.length = keys.length)
    (hv : ∀ c, c < vals.length → ρ (vals.getD c 0) = QM31.fromBase (x c))
    (hk : ∀ c, c < vals.length → ρ (keys.getD c 0) = uQ * QM31.fromBase (K c))
    (h : AllHold ρ (sortCoreG one vals keys n).ops) :
    let s := (lanewise2 .add vals keys n).next
    let m := vals.length
    (((List.range m).map (s + ·)).map ρ).Perm ((List.range m).map fun c => tq (x c) (K c)) ∧
    (sortCoreG one vals keys n).res.1.length = m ∧ (sortCoreG one vals keys n).res.2.length = m ∧
    ∀ k, k < m →
      ρ ((sortCoreG one vals keys n).res.1.getD k 0) = pmulQ (ρ (s + k)) 1 ∧
      ρ ((sortCoreG one vals keys n).res.2.getD k 0) = ρ (s + k) - pmulQ (ρ (s + k)) 1 := by
  intro s m
  have htl : (lanewise2 .add vals keys n).res.length = m := by
    rw [lanewise2_length, ← hlen, Nat.min_self]
  rw [show (sortCoreG one vals keys n).ops =
    (lanewise2 .add vals keys n).ops ++
      [.perm ((List.range m).map (s + ·)) (lanewise2 .add vals keys n).res] ++
      (List.range m).flatMap (fun k =>
        [.pmul (s + m + 2 * k) (s + k) one, .sub (s + m + 2 * k + 1) (s + k) (s + m + 2 * k)])
    by unfold sortCoreG; dsimp only; rw [htl], allHold_append, allHold_append] at h
  obtain ⟨⟨htag, hp⟩, hsp⟩ := h
  have hp' := hp _ List.mem_cons_self
  simp only [Holds] at hp'
  have htagv : (lanewise2 .add vals keys n).res.map ρ
      = (List.range m).map fun c => tq (x c) (K c) := by
    refine List.ext_getElem (by simp [htl]) fun c h1 h2 => ?_
    have hc : c < m := by simpa using h2
    have := lanewise2_sound (· + ·) .add (fun _ _ _ _ h => h) vals keys n htag c
      (by rw [htl]; exact hc)
    rw [List.getElem_map, ← List.getD_eq_getElem _ 0 (by rw [htl]; exact hc), this,
      hv c hc, hk c hc, tag_eq]
    simp
  refine ⟨?_, ?_, ?_, ?_⟩
  · rw [← htagv]; exact hp'.symm
  · show ((List.range (lanewise2 .add vals keys n).res.length).map _).length = m
    simp [htl]
  · show ((List.range (lanewise2 .add vals keys n).res.length).map _).length = m
    simp [htl]
  · intro k hkm
    have hpm : ρ (s + m + 2 * k) = pmulQ (ρ (s + k)) (ρ one) :=
      hsp _ (List.mem_flatMap.mpr ⟨k, List.mem_range.mpr hkm, List.mem_cons_self⟩)
    have hsb : ρ (s + m + 2 * k + 1) = ρ (s + k) - ρ (s + m + 2 * k) :=
      hsp _ (List.mem_flatMap.mpr ⟨k, List.mem_range.mpr hkm,
        List.mem_cons_of_mem _ List.mem_cons_self⟩)
    have hr1 : (sortCoreG one vals keys n).res.1.getD k 0 = s + m + 2 * k := by
      show ((List.range (lanewise2 .add vals keys n).res.length).map _).getD k 0 = _
      rw [htl, getD_range_map _ hkm]
    have hr2 : (sortCoreG one vals keys n).res.2.getD k 0 = s + m + 2 * k + 1 := by
      show ((List.range (lanewise2 .add vals keys n).res.length).map _).getD k 0 = _
      rw [htl, getD_range_map _ hkm]
    rw [hr1, hr2, hsb, hpm, hone]
    exact ⟨rfl, rfl⟩

theorem verifyFirstG_sound {ρ : ℕ → QM31} {zero uinv : ℕ} {keys : List ℕ} {kb n : ℕ}
    (hzero : ρ zero = 0) (huinv : ρ uinv = uQ⁻¹) (hkb1 : 1 ≤ kb) (hkb : kb ≤ 30)
    (kv : ℕ → F) (hk : ∀ c, c < keys.length → ρ (keys.getD c 0) = uQ * QM31.fromBase (kv c))
    (h : AllHold ρ (verifyFirstG zero uinv keys kb n).ops) :
    ∀ k, k + 1 < keys.length → (kv (k + 1) - kv k).val < 2 ^ kb := by
  set m := keys.length with hmdef
  set dregs := (List.range (m - 1)).map fun k => n + 2 * k + 1 with hdregs
  set pk := packG dregs (n + 2 * (m - 1)) with hpk
  rw [show (verifyFirstG zero uinv keys kb n).ops =
    (List.range (m - 1)).flatMap (fun k =>
      [.sub (n + 2 * k) (keys.getD (k + 1) 0) (keys.getD k 0),
       .mul (n + 2 * k + 1) (n + 2 * k) uinv]) ++ pk.ops ++
      (extractBitsK zero pk.res kb pk.next).ops from rfl,
    allHold_append, allHold_append] at h
  obtain ⟨⟨hd, hpkh⟩, heb⟩ := h
  have hdv : ∀ k, k < m - 1 → ρ (dregs.getD k 0) = QM31.fromBase (kv (k + 1) - kv k) := by
    intro k hk'
    have hs : ρ (n + 2 * k) = _ :=
      hd _ (List.mem_flatMap.mpr ⟨k, List.mem_range.mpr hk', List.mem_cons_self⟩)
    have hm : ρ (n + 2 * k + 1) = ρ (n + 2 * k) * ρ uinv :=
      hd _ (List.mem_flatMap.mpr ⟨k, List.mem_range.mpr hk',
        List.mem_cons_of_mem _ List.mem_cons_self⟩)
    rw [hdregs, getD_range_map _ hk', hm, hs, hk (k + 1) (by omega), hk k (by omega), huinv,
      diff_eq]
  obtain ⟨hcov, hpl, hpv⟩ := packG_sound (lanes := dregs) (n := n + 2 * (m - 1))
    (fun k => kv (k + 1) - kv k) (fun k hk' => hdv k (by simpa [hdregs] using hk')) hpkh
  intro k hk'
  have hkl : k < pk.res.len := by rw [hpl]; simp [hdregs]; omega
  obtain ⟨hbits, hnat⟩ := extractBitsK_sound hzero hcov hkb1 hkb heb k hkl
  have hlt := BitDecomp.natOf_lt _ kb hbits
  rw [hnat, hpv k (by simp [hdregs]; omega)] at hlt
  exact hlt

/-- **The first sort of a tree**: the low parts are the query's values in
`columnOrder`, the keys the column keys in that order. -/
theorem sortFirst_sound {ρ : ℕ → QM31} {zero one uinv : ℕ} {vals keys : List ℕ} {n : ℕ}
    (logs : List ℕ) (b : ℕ) (x : ℕ → F) (hzero : ρ zero = 0) (hone : ρ one = 1)
    (huinv : ρ uinv = uQ⁻¹) (hb : 5 + b ≤ 30)
    (hm : logs.length ≤ 2 ^ b) (hlogs : ∀ c, c < logs.length → logs.getD c 0 < 2 ^ 5)
    (hvl : vals.length = logs.length) (hkl : keys.length = logs.length)
    (hv : ∀ c, c < logs.length → ρ (vals.getD c 0) = QM31.fromBase (x c))
    (hk : ∀ c, c < logs.length →
      ρ (keys.getD c 0) = uQ * QM31.fromBase ((colKey logs b c : ℕ) : F))
    (hcore : AllHold ρ (sortCoreG one vals keys n).ops)
    (hver : AllHold ρ (verifyFirstG zero uinv (sortCoreG one vals keys n).res.2 (5 + b)
      (sortCoreG one vals keys n).next).ops) :
    ∀ k, k < logs.length →
      ρ ((sortCoreG one vals keys n).res.1.getD k 0)
        = QM31.fromBase (x ((columnOrder logs).getD k 0)) ∧
      ρ ((sortCoreG one vals keys n).res.2.getD k 0)
        = uQ * QM31.fromBase ((colKey logs b ((columnOrder logs).getD k 0) : ℕ) : F) := by
  obtain ⟨hperm, hl1, hl2, hsplit⟩ := sortCore_sound x
    (fun c => ((colKey logs b c : ℕ) : F)) hone (by rw [hvl, hkl])
    (fun c hc => hv c (by omega)) (fun c hc => hk c (by omega)) hcore
  set s := (lanewise2 .add vals keys n).next with hs
  set S := ((List.range vals.length).map (s + ·)).map ρ with hS
  have hSlen : S.length = logs.length := by simp [hS, hvl]
  have hSk : ∀ k (hk' : k < S.length), S[k] = ρ (s + k) := by
    intro k hk'; simp [hS]
  have hmem : ∀ k (hk' : k < S.length), ∃ c, c < logs.length ∧
      S[k] = tq (x c) ((colKey logs b c : ℕ) : F) := by
    intro k hk'
    obtain ⟨c, hc, he⟩ := List.mem_map.mp (hperm.mem_iff.mp (List.getElem_mem hk'))
    exact ⟨c, by simpa [hvl] using hc, he.symm⟩
  have hkeys : ∀ k, k < (sortCoreG one vals keys n).res.2.length →
      ρ ((sortCoreG one vals keys n).res.2.getD k 0) = uQ * QM31.fromBase (kf (ρ (s + k))) := by
    intro k hk'
    have hk2 : k < S.length := by rw [hSlen, ← hvl, ← hl2]; exact hk'
    obtain ⟨c, hc, he⟩ := hmem k hk2
    rw [(hsplit k (by rw [← hl2]; exact hk')).2, ← hSk k hk2, he, low_eq, key_eq, kf_tq]
  have hdiffs := verifyFirstG_sound hzero huinv (by omega) hb
    (fun k => kf (ρ (s + k))) hkeys hver
  have heq := sorted_eq_columnOrder logs b (5 + b) x rfl hb hm hlogs S
    (by rw [hvl] at hperm; exact hperm)
    (fun k hk' => by
      rw [hSk, hSk]
      exact hdiffs k (by rw [hl2]; rw [hSlen] at hk'; omega))
  intro k hk'
  have hk2 : k < S.length := by rw [hSlen]; exact hk'
  have hco : (columnOrder logs).length = logs.length :=
    (ColumnOrder.columnOrder_perm logs).length_eq.trans (List.length_range)
  have hSv : S[k] = tq (x ((columnOrder logs).getD k 0))
      ((colKey logs b ((columnOrder logs).getD k 0) : ℕ) : F) := by
    have := congrArg (fun l => l[k]?) heq
    simp only [List.getElem?_eq_getElem hk2, List.getElem?_map,
      List.getElem?_eq_getElem (show k < (columnOrder logs).length by rw [hco]; exact hk'),
      Option.map_some, Option.some.injEq] at this
    rw [this, List.getD_eq_getElem?_getD, List.getElem?_eq_getElem
      (show k < (columnOrder logs).length by rw [hco]; exact hk')]
    rfl
  obtain ⟨h1, h2⟩ := hsplit k (by rw [← hvl] at hk'; exact hk')
  rw [h1, h2, ← hSk k hk2, hSv, low_eq, key_eq]
  exact ⟨rfl, rfl⟩

theorem columnOrder_getD_lt (logs : List ℕ) {k : ℕ} (hk : k < logs.length) :
    (columnOrder logs).getD k 0 < logs.length := by
  have hco : (columnOrder logs).length = logs.length :=
    (ColumnOrder.columnOrder_perm logs).length_eq.trans (List.length_range)
  rw [List.getD_eq_getElem?_getD, List.getElem?_eq_getElem (by rw [hco]; exact hk)]
  exact List.mem_range.mp ((ColumnOrder.columnOrder_perm logs).mem_iff.mp (List.getElem_mem _))

theorem fromBase_inj {a b : F} (h : QM31.fromBase a = QM31.fromBase b) : a = b := by
  have := congrArg (fun q : QM31 => q.c0.a) h
  simpa [QM31.fromBase, CM31.fromBase] using this

/-- **A later sort of the same tree**: keys pinned to the first sort's
give the same column order. -/
theorem sortLater_sound {ρ : ℕ → QM31} {one : ℕ} {vals keys first : List ℕ} {n : ℕ}
    (logs : List ℕ) (b : ℕ) (x : ℕ → F) (hone : ρ one = 1) (hb : 5 + b ≤ 30)
    (hm : logs.length ≤ 2 ^ b) (hlogs : ∀ c, c < logs.length → logs.getD c 0 < 2 ^ 5)
    (hvl : vals.length = logs.length) (hkl : keys.length = logs.length)
    (hv : ∀ c, c < logs.length → ρ (vals.getD c 0) = QM31.fromBase (x c))
    (hk : ∀ c, c < logs.length →
      ρ (keys.getD c 0) = uQ * QM31.fromBase ((colKey logs b c : ℕ) : F))
    (hfirst : ∀ k, k < logs.length → ρ (first.getD k 0)
      = uQ * QM31.fromBase ((colKey logs b ((columnOrder logs).getD k 0) : ℕ) : F))
    (hcore : AllHold ρ (sortCoreG one vals keys n).ops)
    (heqs : AllHold ρ (keysEqG (sortCoreG one vals keys n).res.2 first)) :
    ∀ k, k < logs.length →
      ρ ((sortCoreG one vals keys n).res.1.getD k 0)
        = QM31.fromBase (x ((columnOrder logs).getD k 0)) := by
  obtain ⟨hperm, hl1, hl2, hsplit⟩ := sortCore_sound x
    (fun c => ((colKey logs b c : ℕ) : F)) hone (by rw [hvl, hkl])
    (fun c hc => hv c (by omega)) (fun c hc => hk c (by omega)) hcore
  set s := (lanewise2 .add vals keys n).next with hs
  intro k hk'
  have hkS : k < ((List.range vals.length).map (s + ·)).length := by simp [hvl]; exact hk'
  obtain ⟨c, hc, he⟩ := List.mem_map.mp (hperm.mem_iff.mp (List.getElem_mem
    (show k < (((List.range vals.length).map (s + ·)).map ρ).length by simpa using hkS)))
  have hcm : c < logs.length := by simpa [hvl] using hc
  have hSk : ρ (s + k) = tq (x c) ((colKey logs b c : ℕ) : F) := by
    have := he
    simp only [List.getElem_map, List.getElem_range] at this
    exact this.symm
  obtain ⟨h1, h2⟩ := hsplit k (by rw [hvl]; exact hk')
  have heq : ρ ((sortCoreG one vals keys n).res.2.getD k 0) = ρ (first.getD k 0) :=
    heqs _ (List.mem_map.mpr ⟨k, List.mem_range.mpr (by rw [hl2, hvl]; exact hk'), rfl⟩)
  rw [h2, hSk, low_eq, key_eq, hfirst k hk'] at heq
  have hK := fromBase_inj (mul_left_cancel₀ uQ_ne_zero heq)
  have hord := columnOrder_getD_lt logs hk'
  have hlt : ∀ j, j < logs.length → colKey logs b j < P := fun j hj => by
    have := colKey_lt (hlogs j hj) (show j < 2 ^ b by omega)
    have : 2 ^ (5 + b) ≤ 2 ^ 30 := Nat.pow_le_pow_right (by norm_num) hb
    unfold P; omega
  have hval := congrArg ZMod.val hK
  rw [ZMod.val_cast_of_lt (hlt c hcm), ZMod.val_cast_of_lt (hlt _ hord)] at hval
  have hco := colKey_inj (show c < 2 ^ b by omega) (show _ < 2 ^ b by omega) hval
  rw [h1, hSk, low_eq, hco]

end StwoVerifier.Gadgets
