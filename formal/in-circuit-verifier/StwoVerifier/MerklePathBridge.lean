/-
**From the circuit's per-query path to `MerkleBatch.Paths`.**

`verifyPathG_sound` pins a root to `pathRoot` of a leaf along the auth
path with the query's bits; `MerkleBatch` reasons with `nodeAt`, the
query's level-`l` node. `pathRoot_nodeAt` identifies them when the bits
are the position's binary digits. For FRI layers the circuit hashes the
whole coset first (`hash_leaf_qm31` twice, `hash_node`), then walks the
path from the coset node: `friCosetG_sound` gives the root as `pathRoot`
of `nodeHash (lq w₀) (lq w₁)`, which is level 1 of either coset leaf's
query (`cosetMQ_root`).
-/
import StwoVerifier.MerkleGadgets
import StwoVerifier.FriBatch

namespace StwoVerifier.Gadgets

open StwoVerifier StwoVerifier.Gates MerkleBatch

/-- `pathRoot` along a query's own digits is its top node. -/
theorem pathRoot_nodeAt (q : MQ) :
    ∀ m k, m ≤ (q.path.drop k).length →
      pathRoot (nodeAt q k) ((List.range m).map fun t => bitAt q (k + t))
        ((q.path.drop k).take m) = nodeAt q (k + m) := by
  intro m
  induction m with
  | zero => intro k _; cases h : (q.path.drop k) <;> simp [pathRoot]
  | succ m ih =>
    intro k hm
    have hk : k < q.path.length := by simp at hm; omega
    rw [List.range_succ_eq_map, List.map_cons, List.map_map]
    rw [show q.path.drop k = q.path[k] :: q.path.drop (k + 1) from
      (List.drop_eq_getElem_cons hk), List.take_succ_cons]
    show pathRoot (if bitAt q (k + 0) = 0 then Merkle.nodeHash (nodeAt q k) q.path[k]
        else Merkle.nodeHash q.path[k] (nodeAt q k)) _ _ = _
    have hnext : (if bitAt q (k + 0) = 0 then Merkle.nodeHash (nodeAt q k) q.path[k]
        else Merkle.nodeHash q.path[k] (nodeAt q k)) = nodeAt q (k + 1) := by
      rw [Nat.add_zero]
      have : q.path.getD k [] = q.path[k] := by
        rw [List.getD_eq_getElem?_getD, List.getElem?_eq_getElem hk]; rfl
      rw [show nodeAt q (k + 1) = (if bitAt q k = 0 then
          Merkle.nodeHash (nodeAt q k) (q.path.getD k [])
          else Merkle.nodeHash (q.path.getD k []) (nodeAt q k)) from rfl, this]
    rw [hnext]
    have := ih (k + 1) (by simp at hm ⊢; omega)
    rw [show ((fun t => bitAt q (k + t)) ∘ Nat.succ) = fun t => bitAt q (k + 1 + t) from
      funext fun t => by simp [Function.comp, Nat.add_assoc, Nat.add_comm 1 t]]
    rw [this, show k + 1 + m = k + (m + 1) by omega]

/-! ### The FRI coset hash -/

/-- `hash_leaf_qm31`: one QM31 as a 16-byte message. -/
noncomputable def friLeafG (w n : ℕ) : Out (List ℕ) := blake2sFeltsG [w] 16 n

theorem friLeafG_sound {ρ : ℕ → QM31} {w n : ℕ} (h : AllHold ρ (friLeafG w n).ops) :
    ∃ hw, RegsWords ρ (friLeafG w n).res hw ∧ hw.length = 8 ∧
      wordsBytes hw = FriBatch.lq (ρ w) := by
  have hb : (Channel.qm31Bytes (ρ w)).length = 16 := rfl
  have hs := blake2sFeltsG_sound (xs := [ρ w]) (bytes := Channel.qm31Bytes (ρ w))
    (felts := [w]) (n := n) rfl (by intro i hi; simp at hi; subst hi; rfl)
    (by simp [hb]) (by rw [hb]; rfl) (by rw [hb]; exact h)
  refine ⟨_, hs, by simp, ?_⟩
  rw [← digest_eq_wordsBytes]
  rfl

/-- The coset's Merkle check: both leaves, the node, the path. -/
noncomputable def friCosetG (w0 w1 : ℕ) (bits root : List ℕ) (auth : List (List ℕ)) (n : ℕ) :
    Out Unit :=
  let l0 := friLeafG w0 n
  let l1 := friLeafG w1 l0.next
  let nd := blake2sU32sG (l0.res ++ l1.res) 64 l1.next
  let vp := verifyPathG nd.res bits root auth nd.next
  ⟨l0.ops ++ l1.ops ++ nd.ops ++ vp.ops, (), vp.next⟩

theorem friCosetG_sound {ρ : ℕ → QM31} {w0 w1 : ℕ} {bits root : List ℕ}
    {auth : List (List ℕ)} {n : ℕ} {wr : List Blake2s.Word}
    {sws : List (List Blake2s.Word)}
    (hroot : RegsWords ρ root wr) (hr8 : wr.length = 8)
    (hsl : auth.length = sws.length)
    (hsibs : ∀ i, i < auth.length → RegsWords ρ (auth.getD i []) (sws.getD i []) ∧
      (sws.getD i []).length = 8)
    (hbits : ∀ b ∈ bits, ρ b = 0 ∨ ρ b = 1)
    (h : AllHold ρ (friCosetG w0 w1 bits root auth n).ops) :
    wordsBytes wr = pathRoot (Merkle.nodeHash (FriBatch.lq (ρ w0)) (FriBatch.lq (ρ w1)))
      (bits.map fun b => qbit (ρ b)) (sws.map wordsBytes) := by
  set l0 := friLeafG w0 n with hl0
  set l1 := friLeafG w1 l0.next with hl1
  rw [show (friCosetG w0 w1 bits root auth n).ops =
    l0.ops ++ l1.ops ++ (blake2sU32sG (l0.res ++ l1.res) 64 l1.next).ops ++
      (verifyPathG (blake2sU32sG (l0.res ++ l1.res) 64 l1.next).res bits root auth
        (blake2sU32sG (l0.res ++ l1.res) 64 l1.next).next).ops from rfl] at h
  simp only [allHold_append] at h
  obtain ⟨⟨⟨h0, h1⟩, hn⟩, hp⟩ := h
  obtain ⟨a0, ha0, ha08, hb0⟩ := friLeafG_sound h0
  obtain ⟨a1, ha1, ha18, hb1⟩ := friLeafG_sound h1
  have hcat := regsWords_append ha0 ha1
  have h64 : 64 = 4 * (a0 ++ a1).length := by simp [ha08, ha18]
  rw [h64] at hn
  obtain ⟨hw, hrw, h8, hhb⟩ := blakeWords_sound hcat hn
  have hrw' : RegsWords ρ (blake2sU32sG (l0.res ++ l1.res) 64 l1.next).res hw := by
    rw [h64]; exact hrw
  have := verifyPathG_sound hrw' h8 hroot hr8 hsl hsibs hbits hp
  rw [this, hhb, wordsBytes_append, hb0, hb1]
  rfl

theorem div_pow_succ_eq (p t : ℕ) : (p / 2 * 2) / 2 ^ (t + 1) = p / 2 ^ (t + 1) := by
  rw [pow_succ', ← Nat.div_div_eq_div_mul, ← Nat.div_div_eq_div_mul,
    show p / 2 * 2 / 2 = p / 2 by omega]

theorem div_pow_succ_eq' (p t : ℕ) : (p / 2 * 2 + 1) / 2 ^ (t + 1) = p / 2 ^ (t + 1) := by
  rw [pow_succ', ← Nat.div_div_eq_div_mul, ← Nat.div_div_eq_div_mul,
    show (p / 2 * 2 + 1) / 2 = p / 2 by omega]

/-- **A coset leaf's top node is the circuit's path root** from the
coset node, along the position's upper digits. -/
theorem cosetMQ_root (q : FriBatch.FQ) {h : ℕ} (hh : 1 ≤ h) (hA : q.auth.length = h - 1) :
    ∀ mq ∈ q.mqs, nodeAt mq h = pathRoot
      (Merkle.nodeHash (FriBatch.lq q.w0) (FriBatch.lq q.w1))
      ((List.range (h - 1)).map fun t => q.pos / 2 ^ (t + 1) % 2) q.auth := by
  intro mq hmq
  simp only [FriBatch.FQ.mqs, List.mem_cons, List.not_mem_nil, or_false] at hmq
  rcases hmq with rfl | rfl
  · have h1 : nodeAt ⟨q.pos / 2 * 2, FriBatch.lq q.w0, FriBatch.lq q.w1 :: q.auth⟩ 1
        = Merkle.nodeHash (FriBatch.lq q.w0) (FriBatch.lq q.w1) := by
      show (if bitAt _ 0 = 0 then _ else _) = _
      rw [if_pos (by unfold bitAt; simp)]
      rfl
    have := pathRoot_nodeAt ⟨q.pos / 2 * 2, FriBatch.lq q.w0, FriBatch.lq q.w1 :: q.auth⟩
      (h - 1) 1 (by simp [hA])
    rw [h1, show 1 + (h - 1) = h by omega] at this
    rw [← this]
    simp only [List.drop_one, List.tail_cons, List.take_of_length_le (le_of_eq hA)]
    congr 1
    refine List.map_congr_left fun t _ => ?_
    unfold bitAt
    simp only
    rw [show 1 + t = t + 1 by omega, div_pow_succ_eq]
  · have h1 : nodeAt ⟨q.pos / 2 * 2 + 1, FriBatch.lq q.w1, FriBatch.lq q.w0 :: q.auth⟩ 1
        = Merkle.nodeHash (FriBatch.lq q.w0) (FriBatch.lq q.w1) := by
      show (if bitAt _ 0 = 0 then _ else _) = _
      rw [if_neg (by unfold bitAt; simp)]
      rfl
    have := pathRoot_nodeAt ⟨q.pos / 2 * 2 + 1, FriBatch.lq q.w1, FriBatch.lq q.w0 :: q.auth⟩
      (h - 1) 1 (by simp [hA])
    rw [h1, show 1 + (h - 1) = h by omega] at this
    rw [← this]
    simp only [List.drop_one, List.tail_cons, List.take_of_length_le (le_of_eq hA)]
    congr 1
    refine List.map_congr_left fun t _ => ?_
    unfold bitAt
    simp only
    rw [show 1 + t = t + 1 by omega, div_pow_succ_eq']

end StwoVerifier.Gadgets
