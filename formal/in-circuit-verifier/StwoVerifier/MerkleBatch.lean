/-
**Per-query Merkle paths give an accepting batched decommitment.**

The in-circuit verifier authenticates every query separately
(`verify_merkle_path`: the leaf folded with its own auth path must reach
the root). The native `Merkle.verify` walks the deduplicated, sorted
query set layer by layer, pairing present siblings and consuming one
witness hash per absent sibling. This file proves the step between
them: when every query's path reaches the root, and Blake2s has no
collision among the node messages those paths hash, the batched walk
**succeeds** on an explicit witness (`wits`) and returns the root.

The collision hypothesis is per instance (`Paths.inj`): it ranges only
over the specific messages these queries hash at each level, so it is
satisfiable — a global injectivity assumption on Blake2s would be false
(64-byte messages, 32-byte digests) and make every conclusion vacuous.
Contrapositively, a rejecting batched walk exhibits two of these
concrete messages with one digest.

From the root down, equal digests force equal messages, which forces
equal children: queries agreeing on their position at a level carry
the same node there (`consist`), and the auth-path hash of one query is
its sibling's node when the sibling is also queried (`sib_consist`).
`valAt` reads the level-`l` value of any index off the queries; one
`layerStep` of the spec over `valAt`'s values consumes exactly `wit` and
produces the parent level's values (`layerStep_wit`, `pv_eq`).
-/
import StwoVerifier.Merkle

namespace StwoVerifier.MerkleBatch

open StwoVerifier Merkle Channel

/-! ### Sibling arithmetic -/

theorem xor_one_even (k : ℕ) : (2 * k) ^^^ 1 = 2 * k + 1 := by
  apply Nat.eq_of_testBit_eq
  intro i
  rw [Nat.testBit_xor]
  cases i with
  | zero => simp [Nat.testBit_zero]
  | succ i => simp [Nat.testBit_succ, Nat.mul_add_div]

theorem xor_one_odd (k : ℕ) : (2 * k + 1) ^^^ 1 = 2 * k := by
  apply Nat.eq_of_testBit_eq
  intro i
  rw [Nat.testBit_xor]
  cases i with
  | zero => simp [Nat.testBit_zero]
  | succ i => simp [Nat.testBit_succ, Nat.mul_add_div]

theorem xor_one_div2 (i : ℕ) : (i ^^^ 1) / 2 = i / 2 := by
  rcases Nat.even_or_odd' i with ⟨k, rfl | rfl⟩
  · rw [xor_one_even]; omega
  · rw [xor_one_odd]; omega

theorem xor_one_xor_one (i : ℕ) : (i ^^^ 1) ^^^ 1 = i := by
  rcases Nat.even_or_odd' i with ⟨k, rfl | rfl⟩
  · rw [xor_one_even, xor_one_odd]
  · rw [xor_one_odd, xor_one_even]

theorem blake2s_length (m : Bytes) : (Blake2s.blake2s m).length = 32 := by
  simp [Blake2s.blake2s, Blake2s.digest]

/-! ### One query's path -/

/-- One authenticated query: its position, leaf hash and auth path
(leaf sibling first). -/
structure MQ where
  pos : ℕ
  leaf : Bytes
  path : List Bytes

/-- The query's side at level `l` (`0`: left child). -/
def bitAt (q : MQ) (l : ℕ) : ℕ := q.pos / 2 ^ l % 2

/-- The query's node at level `l` (`0` = the leaf). -/
def nodeAt (q : MQ) : ℕ → Bytes
  | 0 => q.leaf
  | l + 1 => if bitAt q l = 0 then nodeHash (nodeAt q l) (q.path.getD l [])
             else nodeHash (q.path.getD l []) (nodeAt q l)

/-- The message hashed into the level-`l+1` node. -/
def msg (q : MQ) (l : ℕ) : Bytes :=
  if bitAt q l = 0 then nodeAt q l ++ q.path.getD l []
  else q.path.getD l [] ++ nodeAt q l

theorem nodeAt_succ (q : MQ) (l : ℕ) :
    nodeAt q (l + 1) = Blake2s.blake2s (msg q l) := by
  unfold nodeAt msg nodeHash
  split <;> rfl

/-- `pathRoot`-style fold equals the top node. -/
def bitsOf (pos H : ℕ) : List ℕ := (List.range H).map fun l => pos / 2 ^ l % 2

/-- The facts the circuit's per-query checks provide for one tree, plus
the per-instance collision hypothesis. -/
structure Paths (qs : List MQ) (H : ℕ) (root : Bytes) : Prop where
  pos : ∀ q ∈ qs, q.pos < 2 ^ H
  root : ∀ q ∈ qs, nodeAt q H = root
  leaf : ∀ q ∈ qs, q.leaf.length = 32
  path : ∀ q ∈ qs, ∀ l, l < H → (q.path.getD l []).length = 32
  inj : ∀ q ∈ qs, ∀ q' ∈ qs, ∀ l, l < H →
    Blake2s.blake2s (msg q l) = Blake2s.blake2s (msg q' l) → msg q l = msg q' l

section
variable {qs : List MQ} {H : ℕ} {root : Bytes}

theorem nodeAt_length (hP : Paths qs H root) {q : MQ} (hq : q ∈ qs) :
    ∀ l, (nodeAt q l).length = 32
  | 0 => hP.leaf q hq
  | l + 1 => by rw [nodeAt_succ]; exact blake2s_length _

theorem div_succ (p l : ℕ) : p / 2 ^ (l + 1) = p / 2 ^ l / 2 := by
  rw [Nat.div_div_eq_div_mul, pow_succ]

/-- Equal parents: equal messages, by the collision hypothesis. -/
theorem msg_eq (hP : Paths qs H root) {q q' : MQ} (hq : q ∈ qs) (hq' : q' ∈ qs)
    {l : ℕ} (hl : l < H) (h : nodeAt q (l + 1) = nodeAt q' (l + 1)) :
    msg q l = msg q' l := by
  rw [nodeAt_succ, nodeAt_succ] at h
  exact hP.inj q hq q' hq' l hl h

/-- Same index at level `l` and equal parents: equal nodes and siblings. -/
theorem same_children (hP : Paths qs H root) {q q' : MQ} (hq : q ∈ qs)
    (hq' : q' ∈ qs) {l : ℕ} (hl : l < H)
    (hidx : q.pos / 2 ^ l = q'.pos / 2 ^ l)
    (h : nodeAt q (l + 1) = nodeAt q' (l + 1)) :
    nodeAt q l = nodeAt q' l ∧ q.path.getD l [] = q'.path.getD l [] := by
  have hm := msg_eq hP hq hq' hl h
  have hb : bitAt q l = bitAt q' l := by unfold bitAt; rw [hidx]
  unfold msg at hm
  rw [hb] at hm
  split at hm
  · exact List.append_inj hm (by rw [nodeAt_length hP hq, nodeAt_length hP hq'])
  · have := List.append_inj hm (by rw [hP.path q hq l hl, hP.path q' hq' l hl])
    exact ⟨this.2, this.1⟩

/-- **Downward consistency**: queries agreeing on their level-`l`
index carry the same node there. -/
theorem consist (hP : Paths qs H root) :
    ∀ k l, l + k = H → ∀ q ∈ qs, ∀ q' ∈ qs,
      q.pos / 2 ^ l = q'.pos / 2 ^ l → nodeAt q l = nodeAt q' l := by
  intro k
  induction k with
  | zero =>
    intro l hl q hq q' hq' _
    rw [show l = H by omega, hP.root q hq, hP.root q' hq']
  | succ k ih =>
    intro l hl q hq q' hq' hidx
    have hup : q.pos / 2 ^ (l + 1) = q'.pos / 2 ^ (l + 1) := by
      rw [div_succ, div_succ, hidx]
    exact (same_children hP hq hq' (by omega) hidx
      (ih (l + 1) (by omega) q hq q' hq' hup)).1

theorem consist' (hP : Paths qs H root) {l : ℕ} (hl : l ≤ H) {q q' : MQ}
    (hq : q ∈ qs) (hq' : q' ∈ qs) (hidx : q.pos / 2 ^ l = q'.pos / 2 ^ l) :
    nodeAt q l = nodeAt q' l :=
  consist hP (H - l) l (by omega) q hq q' hq' hidx

/-- Same index below the root: equal auth-path entries. -/
theorem path_consist (hP : Paths qs H root) {l : ℕ} (hl : l < H) {q q' : MQ}
    (hq : q ∈ qs) (hq' : q' ∈ qs) (hidx : q.pos / 2 ^ l = q'.pos / 2 ^ l) :
    q.path.getD l [] = q'.path.getD l [] := by
  have hup : q.pos / 2 ^ (l + 1) = q'.pos / 2 ^ (l + 1) := by
    rw [div_succ, div_succ, hidx]
  exact (same_children hP hq hq' hl hidx (consist' hP (by omega) hq hq' hup)).2

/-- **Sibling consistency**: a left query's auth-path hash is its right
sibling query's node, and conversely. -/
theorem sib_consist (hP : Paths qs H root) {l : ℕ} (hl : l < H) {q q' : MQ}
    (hq : q ∈ qs) (hq' : q' ∈ qs) {j : ℕ}
    (h0 : q.pos / 2 ^ l = 2 * j) (h1 : q'.pos / 2 ^ l = 2 * j + 1) :
    q.path.getD l [] = nodeAt q' l ∧ nodeAt q l = q'.path.getD l [] := by
  have hup : q.pos / 2 ^ (l + 1) = q'.pos / 2 ^ (l + 1) := by
    rw [div_succ, div_succ, h0, h1]; omega
  have hm := msg_eq hP hq hq' hl (consist' hP (by omega) hq hq' hup)
  have hb0 : bitAt q l = 0 := by unfold bitAt; rw [h0]; omega
  have hb1 : bitAt q' l = 1 := by unfold bitAt; rw [h1]; omega
  unfold msg at hm
  rw [hb0, hb1, if_pos rfl, if_neg (by omega)] at hm
  have := List.append_inj hm (by rw [nodeAt_length hP hq, hP.path q' hq' l hl])
  exact ⟨this.2, this.1⟩

end

/-! ### The batched layer walk -/

/-- Parent indices of one layer, mirroring `layerStep`'s pairing. -/
def par : List ℕ → List ℕ
  | [] => []
  | [i] => [i / 2]
  | i :: j :: rest => if i ^^^ 1 = j then i / 2 :: par rest else i / 2 :: par (j :: rest)

/-- The witness hashes `layerStep` consumes on one layer: the value of
every absent sibling. -/
def wit (f : ℕ → Bytes) : List ℕ → List Bytes
  | [] => []
  | [i] => [f (i ^^^ 1)]
  | i :: j :: rest => if i ^^^ 1 = j then wit f rest else f (i ^^^ 1) :: wit f (j :: rest)

/-- The parent value of node `j` from its children's values. -/
def pvAt (f : ℕ → Bytes) (j : ℕ) : Bytes := nodeHash (f (2 * j)) (f (2 * j + 1))

theorem parent_eq (f : ℕ → Bytes) (i : ℕ) :
    (if i % 2 = 0 then nodeHash (f i) (f (i ^^^ 1)) else nodeHash (f (i ^^^ 1)) (f i))
      = pvAt f (i / 2) := by
  rcases Nat.even_or_odd' i with ⟨k, rfl | rfl⟩
  · rw [if_pos (by omega), xor_one_even, show 2 * k / 2 = k by omega]
    rfl
  · rw [if_neg (by omega), xor_one_odd, show (2 * k + 1) / 2 = k by omega]
    rfl

theorem lt_xor_even {i : ℕ} (h : i < i ^^^ 1) : i % 2 = 0 := by
  rcases Nat.even_or_odd' i with ⟨k, rfl | rfl⟩
  · omega
  · rw [xor_one_odd] at h; omega

/-- **One spec layer step over level values** consumes `wit` and
yields the parents' values. -/
theorem layerStep_wit (f : ℕ → Bytes) :
    ∀ (n : ℕ) (idx : List ℕ), idx.length ≤ n → idx.Pairwise (· < ·) →
      ∀ rest, layerStep (idx.map fun i => (i, f i)) (wit f idx ++ rest)
        = .ok ((par idx).map (fun j => (j, pvAt f j)), rest) := by
  intro n
  induction n with
  | zero =>
    intro idx hl _ rest
    rw [List.eq_nil_of_length_eq_zero (by omega : idx.length = 0)]
    rfl
  | succ n ih =>
    intro idx hl hs rest
    match idx, hl, hs with
    | [], _, _ => rfl
    | [i], _, _ =>
      show layerStep [(i, f i)] (f (i ^^^ 1) :: rest) = _
      simp only [layerStep]
      rw [parent_eq]
      rfl
    | i :: j :: rs, hl, hs =>
      have hs' := List.pairwise_cons.mp hs
      by_cases hx : i ^^^ 1 = j
      · have hev : i % 2 = 0 := lt_xor_even (by rw [hx]; exact hs'.1 j List.mem_cons_self)
        have hrest : rs.Pairwise (· < ·) := (List.pairwise_cons.mp hs'.2).2
        have ihr := ih rs (by simp at hl; omega) hrest rest
        have hw : wit f (i :: j :: rs) = wit f rs := by
          show (if i ^^^ 1 = j then wit f rs else f (i ^^^ 1) :: wit f (j :: rs)) = _
          rw [if_pos hx]
        have hp : par (i :: j :: rs) = i / 2 :: par rs := by
          show (if i ^^^ 1 = j then i / 2 :: par rs else i / 2 :: par (j :: rs)) = _
          rw [if_pos hx]
        rw [hw, hp]
        show layerStep ((i, f i) :: (j, f j) :: rs.map fun i => (i, f i))
          (wit f rs ++ rest) = _
        simp only [layerStep, if_pos hx]
        rw [ihr]
        have hpv : nodeHash (f i) (f j) = pvAt f (i / 2) := by
          rw [← parent_eq, if_pos hev, hx]
        simp only [hpv]
        rfl
      · have ihr := ih (j :: rs) (by simp at hl ⊢; omega) hs'.2 rest
        have hw : wit f (i :: j :: rs) = f (i ^^^ 1) :: wit f (j :: rs) := by
          show (if i ^^^ 1 = j then wit f rs else f (i ^^^ 1) :: wit f (j :: rs)) = _
          rw [if_neg hx]
        have hp : par (i :: j :: rs) = i / 2 :: par (j :: rs) := by
          show (if i ^^^ 1 = j then i / 2 :: par rs else i / 2 :: par (j :: rs)) = _
          rw [if_neg hx]
        rw [hw, hp]
        show layerStep ((i, f i) :: (j, f j) :: rs.map fun i => (i, f i))
          (f (i ^^^ 1) :: (wit f (j :: rs) ++ rest)) = _
        simp only [layerStep, if_neg hx]
        rw [show ((j, f j) :: rs.map fun i => (i, f i)) = (j :: rs).map (fun i => (i, f i))
          from rfl, ihr, parent_eq]
        rfl

theorem mem_par : ∀ (n : ℕ) (idx : List ℕ), idx.length ≤ n →
    ∀ x, x ∈ par idx ↔ ∃ k ∈ idx, x = k / 2 := by
  intro n
  induction n with
  | zero =>
    intro idx hl x
    rw [List.eq_nil_of_length_eq_zero (by omega : idx.length = 0)]
    simp [par]
  | succ n ih =>
    intro idx hl x
    match idx, hl with
    | [], _ => simp [par]
    | [i], _ => simp [par]
    | i :: j :: rs, hl =>
      by_cases hx : i ^^^ 1 = j
      · have hp : par (i :: j :: rs) = i / 2 :: par rs := by
          show (if i ^^^ 1 = j then i / 2 :: par rs else i / 2 :: par (j :: rs)) = _
          rw [if_pos hx]
        rw [hp, List.mem_cons, ih rs (by simp at hl; omega)]
        constructor
        · rintro (rfl | ⟨k, hk, rfl⟩)
          · exact ⟨i, List.mem_cons_self, rfl⟩
          · exact ⟨k, List.mem_cons_of_mem _ (List.mem_cons_of_mem _ hk), rfl⟩
        · rintro ⟨k, hk, rfl⟩
          rcases List.mem_cons.mp hk with rfl | hk
          · exact Or.inl rfl
          rcases List.mem_cons.mp hk with rfl | hk
          · exact Or.inl (by rw [← hx, xor_one_div2])
          · exact Or.inr ⟨k, hk, rfl⟩
      · have hp : par (i :: j :: rs) = i / 2 :: par (j :: rs) := by
          show (if i ^^^ 1 = j then i / 2 :: par rs else i / 2 :: par (j :: rs)) = _
          rw [if_neg hx]
        rw [hp, List.mem_cons, ih (j :: rs) (by simp at hl ⊢; omega)]
        constructor
        · rintro (rfl | ⟨k, hk, rfl⟩)
          · exact ⟨i, List.mem_cons_self, rfl⟩
          · exact ⟨k, List.mem_cons_of_mem _ hk, rfl⟩
        · rintro ⟨k, hk, rfl⟩
          rcases List.mem_cons.mp hk with rfl | hk
          · exact Or.inl rfl
          · exact Or.inr ⟨k, hk, rfl⟩

theorem mem_par' {idx : List ℕ} {x : ℕ} : x ∈ par idx ↔ ∃ k ∈ idx, x = k / 2 :=
  mem_par idx.length idx le_rfl x

theorem par_sorted : ∀ (n : ℕ) (idx : List ℕ), idx.length ≤ n →
    idx.Pairwise (· < ·) → (par idx).Pairwise (· < ·) := by
  intro n
  induction n with
  | zero =>
    intro idx hl _
    rw [List.eq_nil_of_length_eq_zero (by omega : idx.length = 0)]
    simp [par]
  | succ n ih =>
    intro idx hl hs
    match idx, hl, hs with
    | [], _, _ => simp [par]
    | [i], _, _ => simp [par]
    | i :: j :: rs, hl, hs =>
      have hs' := List.pairwise_cons.mp hs
      have hs'' := List.pairwise_cons.mp hs'.2
      by_cases hx : i ^^^ 1 = j
      · have hp : par (i :: j :: rs) = i / 2 :: par rs := by
          show (if i ^^^ 1 = j then i / 2 :: par rs else i / 2 :: par (j :: rs)) = _
          rw [if_pos hx]
        have hev : i % 2 = 0 := lt_xor_even (by rw [hx]; exact hs'.1 j List.mem_cons_self)
        have hj : j = i + 1 := by
          rw [← hx]
          obtain ⟨k, rfl⟩ : ∃ k, i = 2 * k := ⟨i / 2, by omega⟩
          rw [xor_one_even]
        rw [hp, List.pairwise_cons]
        refine ⟨?_, ih rs (by simp at hl; omega) hs''.2⟩
        intro a ha
        obtain ⟨k, hk, rfl⟩ := mem_par'.mp ha
        have := hs''.1 k hk
        omega
      · have hp : par (i :: j :: rs) = i / 2 :: par (j :: rs) := by
          show (if i ^^^ 1 = j then i / 2 :: par rs else i / 2 :: par (j :: rs)) = _
          rw [if_neg hx]
        rw [hp, List.pairwise_cons]
        refine ⟨?_, ih (j :: rs) (by simp at hl ⊢; omega) hs'.2⟩
        intro a ha
        obtain ⟨k, hk, rfl⟩ := mem_par'.mp ha
        have hij : i < j := hs'.1 j List.mem_cons_self
        have hjk : j ≤ k := by
          rcases List.mem_cons.mp hk with rfl | hk
          · exact le_rfl
          · exact le_of_lt (hs''.1 k hk)
        rcases Nat.even_or_odd' i with ⟨t, rfl | rfl⟩
        · rw [xor_one_even] at hx
          omega
        · omega

/-- The level-`l` index list of the batched walk. -/
def idxAt (uniq : List ℕ) : ℕ → List ℕ
  | 0 => uniq
  | l + 1 => par (idxAt uniq l)

theorem idxAt_sorted {uniq : List ℕ} (hs : uniq.Pairwise (· < ·)) :
    ∀ l, (idxAt uniq l).Pairwise (· < ·)
  | 0 => hs
  | l + 1 => par_sorted _ _ le_rfl (idxAt_sorted hs l)

theorem mem_idxAt {uniq : List ℕ} :
    ∀ l x, x ∈ idxAt uniq l ↔ ∃ p ∈ uniq, x = p / 2 ^ l
  | 0, x => by simp [idxAt]
  | l + 1, x => by
    show x ∈ par (idxAt uniq l) ↔ _
    rw [mem_par']
    constructor
    · rintro ⟨k, hk, rfl⟩
      obtain ⟨p, hp, rfl⟩ := (mem_idxAt l k).mp hk
      exact ⟨p, hp, by rw [div_succ]⟩
    · rintro ⟨p, hp, rfl⟩
      exact ⟨p / 2 ^ l, (mem_idxAt l _).mpr ⟨p, hp, rfl⟩, by rw [div_succ]⟩

/-- The level-`l` value of index `j`, read off the queries: a queried
node's own value, else (an absent sibling) a query's auth-path hash. -/
def valAt (qs : List MQ) (l j : ℕ) : Bytes :=
  match qs.find? (fun q => q.pos / 2 ^ l = j) with
  | some q => nodeAt q l
  | none =>
    match qs.find? (fun q => q.pos / 2 ^ l = j ^^^ 1) with
    | some q => q.path.getD l []
    | none => []

section
variable {qs : List MQ} {H : ℕ} {root : Bytes}

theorem F_of_mem (hP : Paths qs H root) {l : ℕ} (hl : l ≤ H) {q : MQ} (hq : q ∈ qs)
    {j : ℕ} (hj : q.pos / 2 ^ l = j) : valAt qs l j = nodeAt q l := by
  unfold valAt
  cases hf : qs.find? (fun q => q.pos / 2 ^ l = j) with
  | none =>
    have := List.find?_eq_none.mp hf q hq
    simp [hj] at this
  | some q₁ =>
    have h1 := List.find?_some hf
    have hm := List.mem_of_find?_eq_some hf
    simp only [decide_eq_true_eq] at h1
    exact consist' hP hl hm hq (by rw [h1, hj])

theorem F_of_sib (hP : Paths qs H root) {l : ℕ} (hl : l < H) {q : MQ} (hq : q ∈ qs)
    {j : ℕ} (hj : q.pos / 2 ^ l = j ^^^ 1)
    (habs : ∀ q' ∈ qs, q'.pos / 2 ^ l ≠ j) : valAt qs l j = q.path.getD l [] := by
  unfold valAt
  have hn : qs.find? (fun q => q.pos / 2 ^ l = j) = none :=
    List.find?_eq_none.mpr fun q' hq' => by simpa using habs q' hq'
  rw [hn]
  cases hf : qs.find? (fun q => q.pos / 2 ^ l = j ^^^ 1) with
  | none =>
    have := List.find?_eq_none.mp hf q hq
    simp [hj] at this
  | some q₁ =>
    have h1 := List.find?_some hf
    have hm := List.mem_of_find?_eq_some hf
    simp only [decide_eq_true_eq] at h1
    exact path_consist hP hl hm hq (by rw [h1, hj])

/-- **The parent values are the next level's values** at every index
some query passes through. -/
theorem pv_eq (hP : Paths qs H root) {l : ℕ} (hl : l < H) {q : MQ} (hq : q ∈ qs)
    {j : ℕ} (hj : q.pos / 2 ^ (l + 1) = j) :
    pvAt (valAt qs l) j = valAt qs (l + 1) j := by
  rw [F_of_mem hP (by omega) hq hj, nodeAt]
  rw [div_succ] at hj
  unfold pvAt bitAt
  rcases Nat.mod_two_eq_zero_or_one (q.pos / 2 ^ l) with h0 | h1
  · have hi : q.pos / 2 ^ l = 2 * j := by omega
    rw [if_pos h0, F_of_mem hP (by omega) hq hi]
    congr 1
    by_cases hex : ∃ q' ∈ qs, q'.pos / 2 ^ l = 2 * j + 1
    · obtain ⟨q', hq', h'⟩ := hex
      rw [F_of_mem hP (by omega) hq' h']
      exact (sib_consist hP hl hq hq' hi h').1.symm
    · push Not at hex
      exact F_of_sib hP hl hq (by rw [hi, xor_one_odd]) hex
  · have hi : q.pos / 2 ^ l = 2 * j + 1 := by omega
    rw [if_neg (by omega), F_of_mem hP (by omega) hq hi]
    congr 1
    by_cases hex : ∃ q' ∈ qs, q'.pos / 2 ^ l = 2 * j
    · obtain ⟨q', hq', h'⟩ := hex
      rw [F_of_mem hP (by omega) hq' h']
      exact (sib_consist hP hl hq' hq h' hi).2
    · push Not at hex
      exact F_of_sib hP hl hq (by rw [hi, xor_one_even]) hex

/-- The witness of the whole walk, level by level from `l`. -/
def wits (qs : List MQ) (uniq : List ℕ) : ℕ → ℕ → List Bytes
  | _, 0 => []
  | l, m + 1 => wit (valAt qs l) (idxAt uniq l) ++ wits qs uniq (l + 1) m

theorem walk_from (hP : Paths qs H root) {uniq : List ℕ}
    (hs : uniq.Pairwise (· < ·)) (hmem : ∀ p ∈ uniq, ∃ q ∈ qs, q.pos = p) :
    ∀ m l, l + m = H →
      walk m ((idxAt uniq l).map fun j => (j, valAt qs l j)) (wits qs uniq l m)
        = .ok ((idxAt uniq H).map (fun j => (j, valAt qs H j)), []) := by
  intro m
  induction m with
  | zero =>
    intro l hl
    rw [show l = H by omega]
    rfl
  | succ m ih =>
    intro l hl
    show (do
      let (next, w') ← layerStep ((idxAt uniq l).map fun j => (j, valAt qs l j))
        (wit (valAt qs l) (idxAt uniq l) ++ wits qs uniq (l + 1) m)
      walk m next w') = _
    rw [layerStep_wit (valAt qs l) _ _ le_rfl (idxAt_sorted hs l)]
    have hmap : (par (idxAt uniq l)).map (fun j => (j, pvAt (valAt qs l) j))
        = (idxAt uniq (l + 1)).map (fun j => (j, valAt qs (l + 1) j)) := by
      refine List.map_congr_left fun j hj => ?_
      obtain ⟨p, hp, rfl⟩ := (mem_idxAt (l + 1) j).mp hj
      obtain ⟨q, hq, rfl⟩ := hmem p hp
      rw [pv_eq hP (by omega) hq rfl]
    rw [hmap]
    exact ih (l + 1) (by omega)

theorem pairwise_zero {L : List ℕ} (hs : L.Pairwise (· < ·)) (hne : L ≠ [])
    (h0 : ∀ x ∈ L, x = 0) : L = [0] := by
  match L, hs, hne with
  | a :: rest, hs, _ =>
    have ha := h0 a List.mem_cons_self
    subst ha
    cases rest with
    | nil => rfl
    | cons b rest =>
      have := (List.pairwise_cons.mp hs).1 b List.mem_cons_self
      have := h0 b (List.mem_cons_of_mem _ List.mem_cons_self)
      omega

/-- **The batched walk accepts**: from the deduplicated sorted leaf
layer, the spec's `walk` over `wits` ends at the single root with the
witness consumed exactly. -/
theorem walk_paths (hP : Paths qs H root) {uniq : List ℕ}
    (hs : uniq.Pairwise (· < ·)) (hne : uniq ≠ [])
    (hmem : ∀ p ∈ uniq, ∃ q ∈ qs, q.pos = p) :
    walk H (uniq.map fun j => (j, valAt qs 0 j)) (wits qs uniq 0 H)
      = .ok ([(0, root)], []) := by
  have h := walk_from hP hs hmem H 0 (by omega)
  have htop : idxAt uniq H = [0] := by
    refine pairwise_zero (idxAt_sorted hs H) ?_ ?_
    · obtain ⟨p, hp⟩ := List.exists_mem_of_ne_nil uniq hne
      intro hnil
      have := (mem_idxAt H (p / 2 ^ H)).mpr ⟨p, hp, rfl⟩
      rw [hnil] at this
      exact List.not_mem_nil this
    · intro x hx
      obtain ⟨p, hp, rfl⟩ := (mem_idxAt H x).mp hx
      obtain ⟨q, hq, rfl⟩ := hmem p hp
      exact Nat.div_eq_of_lt (hP.pos q hq)
  rw [htop] at h
  obtain ⟨p, hp⟩ := List.exists_mem_of_ne_nil uniq hne
  obtain ⟨q, hq, hqp⟩ := hmem p hp
  have hF : valAt qs H 0 = root := by
    rw [F_of_mem hP le_rfl hq (Nat.div_eq_of_lt (hP.pos q hq)), hP.root q hq]
  have h' : walk H (uniq.map fun j => (j, valAt qs 0 j)) (wits qs uniq 0 H)
      = .ok ((idxAt uniq H).map (fun j => (j, valAt qs H j)), []) := by
    rw [htop]; exact h
  rw [h', htop]
  simp only [List.map_cons, List.map_nil, hF]

end

/-! ### `Merkle.verify` on deduplicated sorted positions -/

theorem mapM_ok' {α β : Type} {f : α → Except VError β} (g : α → β) :
    ∀ l : List α, (∀ x ∈ l, f x = .ok (g x)) → l.mapM f = .ok (l.map g)
  | [], _ => rfl
  | x :: rest, h => by
    rw [List.mapM_cons, h x List.mem_cons_self,
      mapM_ok' g rest fun y hy => h y (List.mem_cons_of_mem x hy)]
    rfl

theorem getElem_lt_of_sorted {ps : List ℕ} (hs : ps.Pairwise (· < ·)) {i j : ℕ}
    (hij : i < j) (hj : j < ps.length) :
    ps.getD i 0 < ps.getD j 0 := by
  rw [List.getD_eq_getElem?_getD, List.getElem?_eq_getElem (by omega),
    List.getD_eq_getElem?_getD, List.getElem?_eq_getElem hj]
  exact List.pairwise_iff_getElem.mp hs i j (by omega) hj hij

/-- On strictly sorted positions the query order is the identity. -/
theorem queryOrder_sorted {ps : List ℕ} (hs : ps.Pairwise (· < ·)) :
    queryOrder ps = List.range ps.length := by
  unfold queryOrder
  refine List.mergeSort_of_pairwise ?_
  refine List.Pairwise.imp_of_mem ?_ List.pairwise_lt_range
  intro a b _ hb hab
  have := getElem_lt_of_sorted hs hab (List.mem_range.mp hb)
  simp only [decide_eq_true_eq]
  omega

theorem sortedUnique_dedup_sorted :
    ∀ {ps : List ℕ}, ps.Pairwise (· < ·) → sortedUnique.dedup ps = ps
  | [], _ => rfl
  | [x], _ => rfl
  | x :: y :: rest, hs => by
    have hxy : x < y := (List.pairwise_cons.mp hs).1 y List.mem_cons_self
    show (if x = y then sortedUnique.dedup (y :: rest)
      else x :: sortedUnique.dedup (y :: rest)) = _
    rw [if_neg (by omega), sortedUnique_dedup_sorted (List.pairwise_cons.mp hs).2]

theorem sortedUnique_sorted {ps : List ℕ} (hs : ps.Pairwise (· < ·)) :
    sortedUnique ps = ps := by
  unfold sortedUnique
  rw [List.mergeSort_of_pairwise (hs.imp fun h => by simp only [decide_eq_true_eq]; omega)]
  exact sortedUnique_dedup_sorted hs

theorem dedup_go_sorted (ps : List ℕ) (col : List F) :
    ∀ (ord : List ℕ) (prev : Option ℕ) (acc : List F),
      (ord.map fun i => ps.getD i 0).Pairwise (· < ·) →
      (∀ p, prev = some p → ∀ oi ∈ ord, p < ps.getD oi 0) →
      dedupColumn.go ps col ord prev acc
        = .ok ((ord.map fun i => col.getD i 0).reverse ++ acc)
  | [], _, acc, _, _ => by simp [dedupColumn.go]
  | oi :: rest, prev, acc, hs, hprev => by
    have hne : prev ≠ some (ps.getD oi 0) := by
      intro he
      have := hprev _ he oi List.mem_cons_self
      omega
    show (if prev = some (ps.getD oi 0) then _ else
      dedupColumn.go ps col rest (some (ps.getD oi 0)) (col.getD oi 0 :: acc)) = _
    rw [if_neg hne]
    rw [List.map_cons, List.pairwise_cons] at hs
    rw [dedup_go_sorted ps col rest _ _ hs.2 (by
      intro p hp oi' hoi'
      cases hp
      exact hs.1 _ (List.mem_map_of_mem hoi'))]
    simp

theorem dedupColumn_sorted {ps : List ℕ} (hs : ps.Pairwise (· < ·)) {col : List F}
    (hcol : col.length = ps.length) :
    dedupColumn ps (List.range ps.length) col = .ok col := by
  unfold dedupColumn
  rw [dedup_go_sorted ps col _ none [] ?_ (by intro p hp; cases hp)]
  · show Except.ok (((List.range ps.length).map fun i => col.getD i 0).reverse ++ []).reverse
      = Except.ok col
    rw [List.append_nil, List.reverse_reverse]
    congr 1
    refine List.ext_getElem (by simp [hcol]) fun i h1 h2 => ?_
    rw [List.getElem_map, List.getElem_range, List.getD_eq_getElem?_getD,
      List.getElem?_eq_getElem h2]
    rfl
  · rw [List.pairwise_map]
    refine List.Pairwise.imp_of_mem ?_ List.pairwise_lt_range
    intro a b _ hb hab
    exact getElem_lt_of_sorted hs hab (List.mem_range.mp hb)

set_option maxHeartbeats 800000 in
/-- **Per-query paths make the spec's `Merkle.verify` accept** on the
sorted deduplicated positions, with the explicit witness `wits`: every
position is some query's, and each query's leaf hash is the spec leaf of
its row (columns in `columnOrder`). -/
theorem verify_paths {qs : List MQ} {H : ℕ} {root : Bytes} (hP : Paths qs H root)
    {uniq : List ℕ} (hs : uniq.Pairwise (· < ·)) (hne : uniq ≠ [])
    (hmem : ∀ p ∈ uniq, ∃ q ∈ qs, q.pos = p)
    (logs : List ℕ) (queried : List (List F))
    (hql : queried.length = logs.length)
    (hcl : ∀ col ∈ queried, col.length = uniq.length)
    (hleaf : ∀ k, k < uniq.length → ∀ q ∈ qs, q.pos = uniq.getD k 0 →
      q.leaf = leafHash ((columnOrder logs).map fun ci => (queried.getD ci []).getD k 0)) :
    Merkle.verify root logs H uniq queried (wits qs uniq 0 H) = .ok () := by
  unfold Merkle.verify
  rw [if_neg (by rw [hql]; exact not_not.mpr rfl)]
  by_cases hemp : logs.isEmpty = true
  · rw [if_pos hemp]; rfl
  rw [if_neg hemp]
  have hany : (queried.any fun col => col.length ≠ uniq.length) = false := by
    rw [List.any_eq_false]
    intro col hc
    simp [hcl col hc]
  rw [if_neg (by rw [hany]; exact Bool.false_ne_true)]
  rw [queryOrder_sorted hs, sortedUnique_sorted hs]
  have hcols : ((columnOrder logs).mapM fun ci =>
      dedupColumn uniq (List.range uniq.length) (queried.getD ci []))
      = .ok ((columnOrder logs).map fun ci => queried.getD ci []) := by
    refine mapM_ok' _ _ fun ci hci => ?_
    refine dedupColumn_sorted hs ?_
    have hci' : ci < queried.length := by
      have := List.mem_range.mp ((List.mergeSort_perm _ _).mem_iff.mp hci)
      rw [hql]; exact this
    exact hcl _ (by
      rw [List.getD_eq_getElem?_getD, List.getElem?_eq_getElem hci']
      exact List.getElem_mem hci')
  dsimp only
  rw [hcols]
  show (do
    let __x ← walk H (uniq.zipIdx.map fun (x : ℕ × ℕ) => (x.1, leafHash
      (((columnOrder logs).map fun ci => queried.getD ci []).map fun col => col.getD x.2 0)))
      (wits qs uniq 0 H)
    match __x with
    | (top, leftover) =>
      if (!leftover.isEmpty) = true then throw VError.witnessTooLong
      else match top with
        | [(_, h)] => if h = root then pure () else throw VError.rootMismatch
        | _ => throw VError.rootMismatch) = Except.ok ()
  have hleaves : (uniq.zipIdx.map fun (x : ℕ × ℕ) => (x.1, leafHash
      (((columnOrder logs).map fun ci => queried.getD ci []).map fun col => col.getD x.2 0)))
      = uniq.map fun j => (j, valAt qs 0 j) := by
    refine List.ext_getElem (by simp) fun k h1 h2 => ?_
    rw [List.getElem_map, List.getElem_zipIdx, List.getElem_map]
    have hk : k < uniq.length := by simpa using h2
    obtain ⟨q, hq, hqp⟩ := hmem _ (List.getElem_mem hk)
    have hgd : uniq.getD k 0 = uniq[k] := by
      rw [List.getD_eq_getElem?_getD, List.getElem?_eq_getElem hk]; rfl
    rw [F_of_mem hP (Nat.zero_le _) hq (by rw [hqp]; simp), nodeAt,
      hleaf k hk q hq (by rw [hqp, hgd]), List.map_map, Nat.zero_add]
    rfl
  simp only [hleaves]
  rw [walk_paths hP hs hne hmem]
  simp only [bind, Except.bind, List.isEmpty_nil, Bool.not_true, Bool.false_eq_true,
    if_false, if_true]
  rfl

end StwoVerifier.MerkleBatch
