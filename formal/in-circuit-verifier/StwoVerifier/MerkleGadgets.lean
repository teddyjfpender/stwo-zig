/-
**The in-circuit Merkle path** (`stark_verifier/merkle.zig`,
stwo-zig `4afa09dbf`).

The circuit authenticates each query on its own: hash the leaf's M31
values as words, then per level conditionally flip node and sibling by
the query bit and hash the pair, and pin the recomputed root word for
word to the absorbed root. Hashes are carried as eight `u32` limb
registers; `wordsBytes` is their byte form, under which every node is
the spec's `Merkle.nodeHash` and the leaf is `Merkle.leafHash`.

The result is the per-query path relation `pathRoot`: the circuit
accepts a query only if folding `nodeHash` along its auth path from
`leafHash row` gives the root. (Relating these per-query paths to the
native batched witness `Merkle.verify` consumes is the proof-conversion
boundary, `verifier_proof.zig`, which stays trusted.)
-/
import StwoVerifier.ChannelGadgets
import StwoVerifier.Merkle

namespace StwoVerifier.Gadgets

open StwoVerifier StwoVerifier.Gates

/-! ### Hash words and bytes -/

/-- The byte form of a word list (each word little-endian). -/
def wordsBytes (ws : List Blake2s.Word) : List UInt8 :=
  (ws.map fun w => Channel.u32Le w.toNat).flatten

theorem wordsBytes_length (ws : List Blake2s.Word) :
    (wordsBytes ws).length = 4 * ws.length := by
  unfold wordsBytes
  rw [List.length_flatten, List.map_map,
    show (List.length ∘ fun w : Blake2s.Word => Channel.u32Le w.toNat)
      = fun _ => 4 from funext fun _ => rfl]
  simp [Nat.mul_comm]

theorem wordsBytes_append (a b : List Blake2s.Word) :
    wordsBytes (a ++ b) = wordsBytes a ++ wordsBytes b := by
  unfold wordsBytes
  rw [List.map_append, List.flatten_append]

theorem digest_eq_wordsBytes (hf : ℕ → Blake2s.Word) :
    Blake2s.digest hf = wordsBytes ((List.range 8).map hf) := by
  unfold Blake2s.digest wordsBytes
  rw [show List.range 8 = [0, 1, 2, 3, 4, 5, 6, 7] from rfl,
    show List.range 4 = [0, 1, 2, 3] from rfl]
  simp [Channel.u32Le]

theorem leWord_wordsBytes (ws : List Blake2s.Word) (pad : List UInt8) {k : ℕ}
    (hk : k < ws.length) :
    Blake2s.leWord (wordsBytes ws ++ pad) k = ws.getD k 0 := by
  have h := leWord_flat_u32Le (ws.map BitVec.toNat) pad
    (fun v hv => by
      obtain ⟨w, -, rfl⟩ := List.mem_map.mp hv
      exact w.isLt) (k := k) (by simpa using hk)
  rw [List.map_map] at h
  unfold wordsBytes
  rw [show (fun w : Blake2s.Word => Channel.u32Le w.toNat)
    = Channel.u32Le ∘ BitVec.toNat from rfl, h,
    getD_map' _ (0 : ℕ) ws k hk]
  rw [List.getD_eq_getElem?_getD, List.getElem?_eq_getElem hk,
    List.getD_eq_getElem?_getD, List.getElem?_eq_getElem hk]
  simp

/-! ### Hashing tracked words -/

/-- **Hashing word registers gives the spec digest's words**: registers
carrying `ws` hash, under `blake2s_u32s` over `4·|ws|` bytes, to
registers whose byte form is `Blake2s.blake2s (wordsBytes ws)`. -/
theorem blakeWords_sound {ρ : ℕ → QM31} {regs : List ℕ}
    {ws : List Blake2s.Word} {n : ℕ}
    (hr : RegsWords ρ regs ws)
    (h : AllHold ρ (blake2sU32sG regs (4 * ws.length) n).ops) :
    ∃ hw, RegsWords ρ (blake2sU32sG regs (4 * ws.length) n).res hw ∧
      hw.length = 8 ∧ wordsBytes hw = Blake2s.blake2s (wordsBytes ws) := by
  have hbl : (wordsBytes ws).length = 4 * ws.length := wordsBytes_length ws
  rw [← hbl] at h
  have hs := blake2sU32sG_sound (bytes := wordsBytes ws) hr
    (by rw [hbl]) (by rw [hbl]; omega)
    (fun k hk => by rw [leWord_wordsBytes ws _ hk]) h
  refine ⟨_, by rw [← hbl]; exact hs, by simp, ?_⟩
  unfold Blake2s.blake2s
  rw [digest_eq_wordsBytes]

/-! ### `cond_flip` -/

/-- `cond_flip`: `diff = sel·(b − a)`, `(a + diff, b − diff)`. -/
def condFlipG (sel a b n : ℕ) : Out (ℕ × ℕ) :=
  ⟨[.sub n b a, .mul (n + 1) sel n, .add (n + 2) a (n + 1),
    .sub (n + 3) b (n + 1)], (n + 2, n + 3), n + 4⟩

theorem condFlipG_sound {ρ : ℕ → QM31} {sel a b n : ℕ}
    (hs : ρ sel = 0 ∨ ρ sel = 1) (h : AllHold ρ (condFlipG sel a b n).ops) :
    ρ (condFlipG sel a b n).res.1 = (if ρ sel = 0 then ρ a else ρ b) ∧
    ρ (condFlipG sel a b n).res.2 = (if ρ sel = 0 then ρ b else ρ a) := by
  simp only [condFlipG, allHold_cons, Holds] at h
  obtain ⟨h1, h2, h3, h4, -⟩ := h
  show ρ (n + 2) = _ ∧ ρ (n + 3) = _
  rw [h3, h4, h2, h1]
  rcases hs with h0 | h1'
  · rw [if_pos h0, if_pos h0, h0]
    constructor <;> ring
  · rw [if_neg (by rw [h1']; exact one_ne_zero), if_neg (by rw [h1']; exact one_ne_zero), h1']
    constructor <;> ring

/-- The word-by-word flips of `merkle_node`. -/
def flipWordsG (sel : ℕ) : List ℕ → List ℕ → ℕ → Out (List ℕ × List ℕ)
  | a :: as, b :: bs, n =>
    let f := condFlipG sel a b n
    let r := flipWordsG sel as bs f.next
    ⟨f.ops ++ r.ops, (f.res.1 :: r.res.1, f.res.2 :: r.res.2), r.next⟩
  | _, _, n => ⟨[], ([], []), n⟩

theorem flipWordsG_sound {ρ : ℕ → QM31} {sel : ℕ}
    (hs : ρ sel = 0 ∨ ρ sel = 1) :
    ∀ (as bs : List ℕ) (wa wb : List Blake2s.Word) (n : ℕ),
      RegsWords ρ as wa → RegsWords ρ bs wb → as.length = bs.length →
      AllHold ρ (flipWordsG sel as bs n).ops →
      RegsWords ρ (flipWordsG sel as bs n).res.1
          (if ρ sel = 0 then wa else wb) ∧
      RegsWords ρ (flipWordsG sel as bs n).res.2
          (if ρ sel = 0 then wb else wa)
  | [], [], wa, wb, n, ha, hb, _, _ => by
    have hwa : wa = [] := List.eq_nil_of_length_eq_zero (by rw [← ha.len]; rfl)
    have hwb : wb = [] := List.eq_nil_of_length_eq_zero (by rw [← hb.len]; rfl)
    subst hwa; subst hwb
    refine ⟨?_, ?_⟩ <;> split <;> exact ⟨rfl, fun j hj => absurd hj (by simp [flipWordsG])⟩
  | [], _ :: _, _, _, _, _, _, hl, _ => by simp at hl
  | _ :: _, [], _, _, _, _, _, hl, _ => by simp at hl
  | a :: as, b :: bs, wa, wb, n, ha, hb, hl, h => by
    cases wa with
    | nil => have := ha.len; simp at this
    | cons x xs =>
      cases wb with
      | nil => have := hb.len; simp at this
      | cons y ys =>
        replace h : AllHold ρ ((condFlipG sel a b n).ops
          ++ (flipWordsG sel as bs (condFlipG sel a b n).next).ops) := h
        rw [allHold_append] at h
        obtain ⟨hf, hr⟩ := h
        have hax : ρ a = packW x := by simpa using ha.val 0 (by simp)
        have hby : ρ b = packW y := by simpa using hb.val 0 (by simp)
        have hta : RegsWords ρ as xs := ⟨by have := ha.len; simpa using this,
          fun j hj => by simpa using ha.val (j + 1) (by simpa using hj)⟩
        have htb : RegsWords ρ bs ys := ⟨by have := hb.len; simpa using this,
          fun j hj => by simpa using hb.val (j + 1) (by simpa using hj)⟩
        obtain ⟨f1, f2⟩ := condFlipG_sound hs hf
        obtain ⟨r1, r2⟩ := flipWordsG_sound hs as bs xs ys _ hta htb
          (by simpa using hl) hr
        have cons_rw : ∀ (r : ℕ) (rs : List ℕ) (w : Blake2s.Word)
            (ws : List Blake2s.Word), ρ r = packW w → RegsWords ρ rs ws →
            RegsWords ρ (r :: rs) (w :: ws) := by
          intro r rs w ws hrw hrs
          refine ⟨by simp [hrs.len], fun j hj => ?_⟩
          cases j with
          | zero => exact hrw
          | succ j => exact hrs.val j (by simpa using hj)
        by_cases h0 : ρ sel = 0
        · rw [if_pos h0] at f1 f2 r1 r2 ⊢
          rw [if_pos h0]
          exact ⟨cons_rw _ _ _ _ (by rw [f1, hax]) r1,
            cons_rw _ _ _ _ (by rw [f2, hby]) r2⟩
        · rw [if_neg h0] at f1 f2 r1 r2 ⊢
          rw [if_neg h0]
          exact ⟨cons_rw _ _ _ _ (by rw [f1, hby]) r1,
            cons_rw _ _ _ _ (by rw [f2, hax]) r2⟩

/-! ### `merkle_node` -/

/-- `merkle_node`: flip by the bit, hash `left ‖ right` (64 bytes). -/
noncomputable def merkleNodeG (node sib : List ℕ) (bit n : ℕ) : Out (List ℕ) :=
  let f := flipWordsG bit node sib n
  let hsh := blake2sU32sG (f.res.1 ++ f.res.2) 64 f.next
  ⟨f.ops ++ hsh.ops, hsh.res, hsh.next⟩

/-- **One path level is the spec's node hash**, children ordered by the
query bit (`1` = the node is the right child). -/
theorem merkleNodeG_sound {ρ : ℕ → QM31} {node sib : List ℕ} {bit n : ℕ}
    {wn ws : List Blake2s.Word}
    (hn : RegsWords ρ node wn) (hs : RegsWords ρ sib ws)
    (hn8 : wn.length = 8) (hs8 : ws.length = 8)
    (hb : ρ bit = 0 ∨ ρ bit = 1)
    (h : AllHold ρ (merkleNodeG node sib bit n).ops) :
    ∃ hw, RegsWords ρ (merkleNodeG node sib bit n).res hw ∧ hw.length = 8 ∧
      wordsBytes hw = (if ρ bit = 0
        then Merkle.nodeHash (wordsBytes wn) (wordsBytes ws)
        else Merkle.nodeHash (wordsBytes ws) (wordsBytes wn)) := by
  replace h : AllHold ρ ((flipWordsG bit node sib n).ops
    ++ (blake2sU32sG ((flipWordsG bit node sib n).res.1
      ++ (flipWordsG bit node sib n).res.2) 64
      (flipWordsG bit node sib n).next).ops) := h
  rw [allHold_append] at h
  obtain ⟨hf, hh⟩ := h
  obtain ⟨fl, fr⟩ := flipWordsG_sound hb node sib wn ws n hn hs
    (by rw [hn.len, hs.len, hn8, hs8]) hf
  have hlr := regsWords_append fl fr
  have h64 : 4 * ((if ρ bit = 0 then wn else ws)
      ++ (if ρ bit = 0 then ws else wn)).length = 64 := by
    split <;> simp [hn8, hs8]
  rw [← h64] at hh
  obtain ⟨hw, hrw, hl8, hbytes⟩ := blakeWords_sound hlr hh
  refine ⟨hw, ?_, hl8, ?_⟩
  · show RegsWords ρ (blake2sU32sG ((flipWordsG bit node sib n).res.1
      ++ (flipWordsG bit node sib n).res.2) 64
      (flipWordsG bit node sib n).next).res hw
    rw [← h64]
    exact hrw
  rw [hbytes, wordsBytes_append]
  unfold Merkle.nodeHash
  split <;> rfl

/-! ### The path -/

/-- The spec's per-query path relation: fold `nodeHash` along the auth
path, the bit choosing the child side. -/
def pathRoot : List UInt8 → List ℕ → List (List UInt8) → List UInt8
  | h, b :: bs, s :: ss =>
    pathRoot (if b = 0 then Merkle.nodeHash h s else Merkle.nodeHash s h) bs ss
  | h, _, _ => h

/-- The level loop of `verify_merkle_path`. -/
noncomputable def pathG : List ℕ → List ℕ → List (List ℕ) → ℕ → Out (List ℕ)
  | node, b :: bs, s :: ss, n =>
    let m := merkleNodeG node s b n
    let r := pathG m.res bs ss m.next
    ⟨m.ops ++ r.ops, r.res, r.next⟩
  | node, _, _, n => ⟨[], node, n⟩

/-- The lane bit as a natural (`0` or `1`). -/
noncomputable def qbit (x : QM31) : ℕ := if x = 0 then 0 else 1

theorem pathG_sound {ρ : ℕ → QM31} :
    ∀ (bits : List ℕ) (sibs : List (List ℕ)) (sws : List (List Blake2s.Word))
      (node : List ℕ) (wn : List Blake2s.Word) (n : ℕ),
      sibs.length = sws.length →
      (∀ i, i < sibs.length → RegsWords ρ (sibs.getD i []) (sws.getD i []) ∧
        (sws.getD i []).length = 8) →
      (∀ b ∈ bits, ρ b = 0 ∨ ρ b = 1) →
      RegsWords ρ node wn → wn.length = 8 →
      AllHold ρ (pathG node bits sibs n).ops →
      ∃ hw, RegsWords ρ (pathG node bits sibs n).res hw ∧ hw.length = 8 ∧
        wordsBytes hw = pathRoot (wordsBytes wn) (bits.map fun b => qbit (ρ b))
          (sws.map wordsBytes)
  | [], sibs, sws, node, wn, n, _, _, _, hn, hn8, _ => by
    refine ⟨wn, hn, hn8, ?_⟩
    cases sws <;> rfl
  | b :: bs, [], sws, node, wn, n, hl, _, _, hn, hn8, _ => by
    have : sws = [] := List.eq_nil_of_length_eq_zero (by rw [← hl]; rfl)
    subst this
    exact ⟨wn, hn, hn8, rfl⟩
  | b :: bs, s :: ss, sws, node, wn, n, hl, hsibs, hbits, hn, hn8, h => by
    cases sws with
    | nil => simp at hl
    | cons sw sws =>
      replace h : AllHold ρ ((merkleNodeG node s b n).ops
        ++ (pathG (merkleNodeG node s b n).res bs ss
          (merkleNodeG node s b n).next).ops) := h
      rw [allHold_append] at h
      obtain ⟨hm, hr⟩ := h
      obtain ⟨hs0, hs8⟩ := hsibs 0 (by simp)
      have hb := hbits b List.mem_cons_self
      obtain ⟨mw, hmrw, hm8, hmb⟩ := merkleNodeG_sound hn hs0 hn8 hs8 hb hm
      obtain ⟨hw, hrw, h8, hpath⟩ := pathG_sound bs ss sws _ mw _
        (by simpa using hl)
        (fun i hi => hsibs (i + 1) (by simpa using hi))
        (fun b' hb' => hbits b' (List.mem_cons_of_mem _ hb')) hmrw hm8 hr
      refine ⟨hw, hrw, h8, ?_⟩
      rw [hpath, hmb]
      show _ = pathRoot (if qbit (ρ b) = 0 then _ else _) _ _
      by_cases h0 : ρ b = 0
      · rw [if_pos h0, show qbit (ρ b) = 0 from by simp [qbit, h0], if_pos rfl]
        rfl
      · rw [if_neg h0, show qbit (ρ b) = 1 from by simp [qbit, h0],
          if_neg (by omega)]
        rfl

/-- `verify_merkle_path`: the level loop, then the recomputed root
pinned word for word to the absorbed root. -/
noncomputable def verifyPathG (leaf : List ℕ) (bits : List ℕ)
    (root : List ℕ) (sibs : List (List ℕ)) (n : ℕ) : Out Unit :=
  let p := pathG leaf bits sibs n
  ⟨p.ops ++ (List.range 8).map (fun i => .eq (p.res.getD i 0) (root.getD i 0)),
   (), p.next⟩

theorem packW_inj {a b : Blake2s.Word} (h : packW a = packW b) : a = b := by
  rw [← wordOf_packW a, h, wordOf_packW]

/-- **A verified path authenticates the leaf against the root**: the
root's byte form is `pathRoot` of the leaf along the auth path. -/
theorem verifyPathG_sound {ρ : ℕ → QM31} {leaf bits root : List ℕ}
    {sibs : List (List ℕ)} {n : ℕ} {wl wr : List Blake2s.Word}
    {sws : List (List Blake2s.Word)}
    (hleaf : RegsWords ρ leaf wl) (hl8 : wl.length = 8)
    (hroot : RegsWords ρ root wr) (hr8 : wr.length = 8)
    (hsl : sibs.length = sws.length)
    (hsibs : ∀ i, i < sibs.length → RegsWords ρ (sibs.getD i []) (sws.getD i []) ∧
      (sws.getD i []).length = 8)
    (hbits : ∀ b ∈ bits, ρ b = 0 ∨ ρ b = 1)
    (h : AllHold ρ (verifyPathG leaf bits root sibs n).ops) :
    wordsBytes wr = pathRoot (wordsBytes wl) (bits.map fun b => qbit (ρ b))
      (sws.map wordsBytes) := by
  replace h : AllHold ρ ((pathG leaf bits sibs n).ops
    ++ (List.range 8).map (fun i =>
      Op.eq ((pathG leaf bits sibs n).res.getD i 0) (root.getD i 0))) := h
  rw [allHold_append] at h
  obtain ⟨hp, heqs⟩ := h
  obtain ⟨hw, hrw, h8, hpath⟩ :=
    pathG_sound bits sibs sws leaf wl n hsl hsibs hbits hleaf hl8 hp
  rw [← hpath]
  congr 1
  refine List.ext_getElem (by rw [hr8, h8]) fun i h1 h2 => ?_
  have hi8 : i < 8 := by omega
  have he := heqs (Op.eq ((pathG leaf bits sibs n).res.getD i 0) (root.getD i 0))
    (List.mem_map.mpr ⟨i, List.mem_range.mpr hi8, rfl⟩)
  simp only [Holds] at he
  rw [hrw.val i (by rw [hrw.len, h8]; exact hi8),
    hroot.val i (by rw [hroot.len, hr8]; exact hi8)] at he
  have := packW_inj he
  rw [List.getD_eq_getElem?_getD, List.getElem?_eq_getElem h2,
    List.getD_eq_getElem?_getD, List.getElem?_eq_getElem h1] at this
  exact this.symm

/-! ### The leaf -/

/-- `hash_leaf_m31s`: each M31 to a `u32` word, then hash. -/
noncomputable def leafG (vals : List ℕ) (n : ℕ) : Out (List ℕ) :=
  let words := (List.range vals.length).map fun i => n + i
  let hsh := blake2sU32sG words (4 * vals.length) (n + vals.length)
  ⟨((List.range vals.length).map fun i => .m2u (n + i) (vals.getD i 0))
    ++ hsh.ops, hsh.res, hsh.next⟩

/-- **The leaf gadget is the spec leaf hash** of the row its value
registers carry. -/
theorem leafG_sound {ρ : ℕ → QM31} {vals : List ℕ} {row : List F} {n : ℕ}
    (hlen : vals.length = row.length)
    (hv : ∀ i, i < vals.length → ρ (vals.getD i 0) = QM31.fromBase (row.getD i 0))
    (h : AllHold ρ (leafG vals n).ops) :
    ∃ hw, RegsWords ρ (leafG vals n).res hw ∧ hw.length = 8 ∧
      wordsBytes hw = Merkle.leafHash row := by
  replace h : AllHold ρ
    (((List.range vals.length).map fun i => Op.m2u (n + i) (vals.getD i 0))
      ++ (blake2sU32sG ((List.range vals.length).map fun i => n + i)
        (4 * vals.length) (n + vals.length)).ops) := h
  rw [allHold_append] at h
  obtain ⟨hm, hh⟩ := h
  set ws := row.map fun v => BitVec.ofNat 32 v.val with hws
  have hwl : ws.length = vals.length := by rw [hws, List.length_map, hlen]
  have hrw : RegsWords ρ ((List.range vals.length).map fun i => n + i) ws := by
    refine ⟨by simp [hwl], fun j hj => ?_⟩
    rw [List.length_map, List.length_range] at hj
    have hg := hm (Op.m2u (n + j) (vals.getD j 0))
      (List.mem_map.mpr ⟨j, List.mem_range.mpr hj, rfl⟩)
    obtain ⟨-, hout⟩ := hg
    rw [getD_map' _ (0 : ℕ) (List.range vals.length) j (by simpa using hj),
      show (List.range vals.length).getD j default = j from by
        rw [List.getD_eq_getElem?_getD, List.getElem?_range hj]; rfl,
      hout, hv j hj, m2uQ_fromBase, hws,
      getD_map' _ (0 : Blake2s.Word) row j (by omega)]
    rfl
  have h4 : 4 * vals.length = 4 * ws.length := by rw [hwl]
  rw [h4] at hh
  obtain ⟨hw, hrw', h8, hb⟩ := blakeWords_sound hrw hh
  refine ⟨hw, ?_, h8, ?_⟩
  · show RegsWords ρ (blake2sU32sG ((List.range vals.length).map fun i => n + i)
      (4 * vals.length) (n + vals.length)).res hw
    rw [h4]
    exact hrw'
  rw [hb]
  unfold Merkle.leafHash wordsBytes
  rw [hws, List.map_map]
  congr 2
  refine List.map_congr_left fun v _ => ?_
  show Channel.u32Le (BitVec.ofNat 32 v.val).toNat = Channel.u32Le v.val
  rw [BitVec.toNat_ofNat, Nat.mod_eq_of_lt
    (lt_of_lt_of_le (ZMod.val_lt v) (by unfold P; norm_num))]

end StwoVerifier.Gadgets
