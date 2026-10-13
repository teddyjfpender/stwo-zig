/-
**Felt ↔ word plumbing for the in-circuit channel**
(`builder/blake.zig` `unpack_qm31s_to_u32_words` / `reduce_hash_value`,
stwo-zig `4afa09dbf`).

A channel message packs four M31 words per QM31 wire;
`unpack_qm31s_to_u32_words` lifts each coordinate (`unpack_idx`) and
converts it to `u32` limbs (`m31_to_u32`). The words are the message
bytes' `leWord`s, so `blake2sU32sG_sound` applies directly.
`reduce_hash_value` folds each digest word back to an M31
(`low + 2¹⁶·high`, the word mod `P`) and packs four per felt
(`from_partial_evals`) — the channel's two-felt digest.
-/
import StwoVerifier.BlakeBridge
import StwoVerifier.OodsGadgets
import StwoVerifier.FriGadgets
import StwoVerifier.Channel

namespace StwoVerifier.Gadgets

open StwoVerifier StwoVerifier.Gates

/-! ### One coordinate to a `u32` word -/

/-- `unpack_idx` then `m31_to_u32`. -/
noncomputable def unpackFeltG (w : ℕ) (c : Nat) (n : ℕ) : Out ℕ :=
  let u := unpackIdx w c n
  ⟨u.ops ++ [.m2u u.next u.res], u.next, u.next + 1⟩

theorem m2uQ_fromBase (v : F) :
    m2uQ (QM31.fromBase v) = packW (BitVec.ofNat 32 v.val) := by
  unfold m2uQ packW
  have hlt : v.val < 2 ^ 32 :=
    lt_of_lt_of_le (ZMod.val_lt v) (by unfold P; norm_num)
  rw [BitVec.toNat_ofNat, Nat.mod_eq_of_lt hlt]
  rfl

theorem unpackFeltG_sound {ρ : ℕ → QM31} {w : ℕ} {c : Nat} {n : ℕ}
    (hc : c < 4) (h : AllHold ρ (unpackFeltG w c n).ops) :
    ρ (unpackFeltG w c n).res
      = packW (BitVec.ofNat 32 (coord (ρ w) c).val) := by
  replace h : AllHold ρ ((unpackIdx w c n).ops
      ++ [.m2u (unpackIdx w c n).next (unpackIdx w c n).res]) := h
  rw [allHold_append, allHold_cons] at h
  obtain ⟨hu, hm, -⟩ := h
  obtain ⟨-, hout⟩ := hm
  show ρ (unpackIdx w c n).next = _
  rw [hout, unpackIdx_sound hc hu, m2uQ_fromBase]

/-! ### All four coordinates of a felt, all felts -/

/-- The four `u32` word wires of one QM31 message wire. -/
noncomputable def feltWordsG (w n : ℕ) : Out (List ℕ) :=
  let u0 := unpackFeltG w 0 n
  let u1 := unpackFeltG w 1 u0.next
  let u2 := unpackFeltG w 2 u1.next
  let u3 := unpackFeltG w 3 u2.next
  ⟨u0.ops ++ u1.ops ++ u2.ops ++ u3.ops,
   [u0.res, u1.res, u2.res, u3.res], u3.next⟩

/-- `unpack_qm31s_to_u32_words`. -/
noncomputable def unpackFeltsG : List ℕ → ℕ → Out (List ℕ)
  | [], n => ⟨[], [], n⟩
  | w :: rest, n =>
    let fw := feltWordsG w n
    let r := unpackFeltsG rest fw.next
    ⟨fw.ops ++ r.ops, fw.res ++ r.res, r.next⟩

/-- The spec words of a felt list: each coordinate's canonical value. -/
def feltWords (xs : List QM31) : List Blake2s.Word :=
  xs.flatMap fun x => x.coords.map fun v => BitVec.ofNat 32 v.val

theorem feltWords_length (xs : List QM31) :
    (feltWords xs).length = 4 * xs.length := by
  unfold feltWords
  rw [List.length_flatMap]
  induction xs with
  | nil => rfl
  | cons x rest ih =>
    rw [List.map_cons, List.sum_cons, ih]
    show (QM31.coords x).length + _ = _
    rw [show (QM31.coords x).length = 4 from rfl, List.length_cons]
    ring

theorem feltWordsG_sound {ρ : ℕ → QM31} {w n : ℕ} {x : QM31}
    (hw : ρ w = x) (h : AllHold ρ (feltWordsG w n).ops) :
    RegsWords ρ (feltWordsG w n).res
      (x.coords.map fun v => BitVec.ofNat 32 v.val) := by
  replace h : AllHold ρ ((unpackFeltG w 0 n).ops
      ++ (unpackFeltG w 1 (unpackFeltG w 0 n).next).ops
      ++ (unpackFeltG w 2 (unpackFeltG w 1 (unpackFeltG w 0 n).next).next).ops
      ++ (unpackFeltG w 3 (unpackFeltG w 2
          (unpackFeltG w 1 (unpackFeltG w 0 n).next).next).next).ops) := h
  rw [allHold_append, allHold_append, allHold_append] at h
  obtain ⟨⟨⟨h0, h1⟩, h2⟩, h3⟩ := h
  have e0 := unpackFeltG_sound (by norm_num) h0
  have e1 := unpackFeltG_sound (by norm_num) h1
  have e2 := unpackFeltG_sound (by norm_num) h2
  have e3 := unpackFeltG_sound (by norm_num) h3
  rw [hw] at e0 e1 e2 e3
  refine ⟨rfl, fun j hj => ?_⟩
  have hj4 : j < 4 := hj
  interval_cases j
  · exact e0
  · exact e1
  · exact e2
  · exact e3

theorem unpackFeltsG_sound {ρ : ℕ → QM31} :
    ∀ (felts : List ℕ) (xs : List QM31) (n : ℕ),
      felts.length = xs.length →
      (∀ i, i < felts.length → ρ (felts.getD i 0) = xs.getD i 0) →
      AllHold ρ (unpackFeltsG felts n).ops →
      RegsWords ρ (unpackFeltsG felts n).res (feltWords xs)
  | [], xs, n, hlen, _, _ => by
    have hxs : xs = [] := List.eq_nil_of_length_eq_zero
      (by simpa using hlen.symm)
    subst hxs
    exact ⟨rfl, fun j hj => absurd (show j < 0 from hj) (by omega)⟩
  | w :: rest, xs, n, hlen, hvals, h => by
    cases xs with
    | nil => simp at hlen
    | cons x xrest =>
      replace h : AllHold ρ ((feltWordsG w n).ops
          ++ (unpackFeltsG rest (feltWordsG w n).next).ops) := h
      rw [allHold_append] at h
      obtain ⟨hfw, hrest⟩ := h
      have hwx : ρ w = x := by
        have := hvals 0 (by simp)
        simpa using this
      have hhead := feltWordsG_sound hwx hfw
      have htail := unpackFeltsG_sound rest xrest (feltWordsG w n).next
        (by simpa using hlen)
        (fun i hi => by
          have := hvals (i + 1) (by simpa using Nat.succ_lt_succ hi)
          simpa using this) hrest
      show RegsWords ρ ((feltWordsG w n).res
        ++ (unpackFeltsG rest (feltWordsG w n).next).res)
        (feltWords (x :: xrest))
      rw [show feltWords (x :: xrest)
        = (x.coords.map fun v => BitVec.ofNat 32 v.val) ++ feltWords xrest
        from by unfold feltWords; rw [List.flatMap_cons]]
      refine ⟨by rw [List.length_append, List.length_append,
        hhead.len, htail.len], fun j hj => ?_⟩
      rw [List.length_append] at hj
      by_cases hjh : j < (feltWordsG w n).res.length
      · rw [List.getD_eq_getElem?_getD, List.getElem?_append_left hjh,
          ← List.getD_eq_getElem?_getD,
          List.getD_eq_getElem?_getD (l := _ ++ feltWords xrest),
          List.getElem?_append_left (by rw [← hhead.len]; exact hjh),
          ← List.getD_eq_getElem?_getD]
        exact hhead.val j hjh
      · push_neg at hjh
        rw [List.getD_eq_getElem?_getD, List.getElem?_append_right hjh,
          ← List.getD_eq_getElem?_getD,
          List.getD_eq_getElem?_getD (l := _ ++ feltWords xrest),
          List.getElem?_append_right (by rw [← hhead.len]; exact hjh),
          ← List.getD_eq_getElem?_getD, hhead.len]
        exact htail.val (j - (feltWordsG w n).res.length) (by
          have := hhead.len
          omega)

/-! ### Reducing the digest back to felts -/

/-- One digest word to M31: `low + 2¹⁶·high` (`reduce_hash_value`'s
loop body). -/
noncomputable def reduceWordG (c16 w n : ℕ) : Out ℕ :=
  let lo := unpackIdx w 0 n
  let hi := unpackIdx w 1 lo.next
  ⟨lo.ops ++ hi.ops ++
    [.mul hi.next hi.res c16, .add (hi.next + 1) lo.res hi.next],
   hi.next + 1, hi.next + 2⟩

theorem reduceWordG_sound {ρ : ℕ → QM31} {c16 w n : ℕ}
    {word : Blake2s.Word}
    (hc : ρ c16 = QM31.fromBase ((65536 : ℕ) : F))
    (hw : ρ w = packW word)
    (h : AllHold ρ (reduceWordG c16 w n).ops) :
    ρ (reduceWordG c16 w n).res = QM31.fromBase ((word.toNat : ℕ) : F) := by
  replace h : AllHold ρ ((unpackIdx w 0 n).ops
      ++ (unpackIdx w 1 (unpackIdx w 0 n).next).ops
      ++ [.mul (unpackIdx w 1 (unpackIdx w 0 n).next).next
            (unpackIdx w 1 (unpackIdx w 0 n).next).res c16,
          .add ((unpackIdx w 1 (unpackIdx w 0 n).next).next + 1)
            (unpackIdx w 0 n).res
            (unpackIdx w 1 (unpackIdx w 0 n).next).next]) := h
  rw [allHold_append, allHold_append, allHold_cons, allHold_cons] at h
  obtain ⟨⟨hlo, hhi⟩, hmul, hadd, -⟩ := h
  simp only [Holds] at hmul hadd
  have elo := unpackIdx_sound (by norm_num) hlo
  have ehi := unpackIdx_sound (by norm_num) hhi
  rw [hw] at elo ehi
  show ρ ((unpackIdx w 1 (unpackIdx w 0 n).next).next + 1) = _
  rw [hadd, hmul, elo, ehi, hc]
  show QM31.fromBase (((word.toNat % 65536 : ℕ) : F))
      + QM31.fromBase (((word.toNat / 65536 : ℕ) : F))
        * QM31.fromBase ((65536 : ℕ) : F) = _
  rw [show ∀ x : F, QM31.fromBase x = baseHom x from fun _ => rfl,
    show ∀ x : F, QM31.fromBase x = baseHom x from fun _ => rfl,
    show ∀ x : F, QM31.fromBase x = baseHom x from fun _ => rfl,
    show ∀ x : F, QM31.fromBase x = baseHom x from fun _ => rfl,
    ← map_mul, ← map_add]
  refine congrArg _ ?_
  push_cast
  rw [show (65536 : F) = ((65536 : ℕ) : F) from by norm_num,
    ← Nat.cast_mul, ← Nat.cast_add, Nat.mod_add_div' word.toNat 65536]

/-- All eight digest words. -/
noncomputable def reduceWordsG (c16 : ℕ) : List ℕ → ℕ → Out (List ℕ)
  | [], n => ⟨[], [], n⟩
  | w :: rest, n =>
    let r0 := reduceWordG c16 w n
    let r := reduceWordsG c16 rest r0.next
    ⟨r0.ops ++ r.ops, r0.res :: r.res, r.next⟩

theorem reduceWordsG_sound {ρ : ℕ → QM31} {c16 : ℕ}
    (hc : ρ c16 = QM31.fromBase ((65536 : ℕ) : F)) :
    ∀ (words : List ℕ) (ws : List Blake2s.Word) (n : ℕ),
      RegsWords ρ words ws →
      AllHold ρ (reduceWordsG c16 words n).ops →
      (reduceWordsG c16 words n).res.length = words.length ∧
      ∀ j, j < words.length →
        ρ ((reduceWordsG c16 words n).res.getD j 0)
          = QM31.fromBase (((ws.getD j 0).toNat : ℕ) : F)
  | [], ws, n, _, _ => ⟨rfl, fun j hj => absurd (show j < 0 from hj) (by omega)⟩
  | w :: rest, ws, n, hrw, h => by
    cases ws with
    | nil =>
      have := hrw.len
      simp at this
    | cons x xrest =>
      replace h : AllHold ρ ((reduceWordG c16 w n).ops
          ++ (reduceWordsG c16 rest (reduceWordG c16 w n).next).ops) := h
      rw [allHold_append] at h
      obtain ⟨h0, hr⟩ := h
      have hhead : ρ w = packW x := by
        have := hrw.val 0 (by simp)
        simpa using this
      have htailrw : RegsWords ρ rest xrest := by
        refine ⟨by have := hrw.len; simpa using this, fun j hj => ?_⟩
        have := hrw.val (j + 1) (by simpa using Nat.succ_lt_succ hj)
        simpa using this
      obtain ⟨ihlen, ihval⟩ := reduceWordsG_sound hc rest xrest
        (reduceWordG c16 w n).next htailrw hr
      refine ⟨by show _ + 1 = _ + 1; rw [ihlen], fun j hj => ?_⟩
      cases j with
      | zero =>
        show ρ (reduceWordG c16 w n).res = _
        rw [reduceWordG_sound hc hhead h0]
        rfl
      | succ j =>
        show ρ ((reduceWordsG c16 rest _).res.getD j 0) = _
        exact ihval j (by simpa using hj)

/-- `reduce_hash_value`: the interned `2¹⁶`, the eight reduced words,
two `from_partial_evals` felts. -/
noncomputable def reduceHashValueG (words : List ℕ) (n : ℕ) :
    Out (ℕ × ℕ) :=
  let rw := reduceWordsG n words (n + 1)
  let lo := fromPartialEvalsG (rw.res.getD 0 0) (rw.res.getD 1 0)
    (rw.res.getD 2 0) (rw.res.getD 3 0) rw.next
  let hi := fromPartialEvalsG (rw.res.getD 4 0) (rw.res.getD 5 0)
    (rw.res.getD 6 0) (rw.res.getD 7 0) lo.next
  ⟨.const n (QM31.fromBase ((65536 : ℕ) : F)) ::
    (rw.ops ++ lo.ops ++ hi.ops), (lo.res, hi.res), hi.next⟩

/-- The channel's two-felt digest of eight words. -/
noncomputable def digestFelts (ws : List Blake2s.Word) : QM31 × QM31 :=
  (fromPartialEvals ((List.range 4).map fun j =>
      QM31.fromBase (((ws.getD j 0).toNat : ℕ) : F)),
   fromPartialEvals ((List.range 4).map fun j =>
      QM31.fromBase (((ws.getD (4 + j) 0).toNat : ℕ) : F)))

theorem reduceHashValueG_sound {ρ : ℕ → QM31} {words : List ℕ}
    {ws : List Blake2s.Word} {n : ℕ}
    (hrw : RegsWords ρ words ws) (h8 : words.length = 8)
    (h : AllHold ρ (reduceHashValueG words n).ops) :
    ρ (reduceHashValueG words n).res.1 = (digestFelts ws).1 ∧
    ρ (reduceHashValueG words n).res.2 = (digestFelts ws).2 := by
  replace h : AllHold ρ
      (Op.const n (QM31.fromBase ((65536 : ℕ) : F)) ::
        ((reduceWordsG n words (n + 1)).ops ++
          (fromPartialEvalsG ((reduceWordsG n words (n + 1)).res.getD 0 0)
            ((reduceWordsG n words (n + 1)).res.getD 1 0)
            ((reduceWordsG n words (n + 1)).res.getD 2 0)
            ((reduceWordsG n words (n + 1)).res.getD 3 0)
            (reduceWordsG n words (n + 1)).next).ops ++
          (fromPartialEvalsG ((reduceWordsG n words (n + 1)).res.getD 4 0)
            ((reduceWordsG n words (n + 1)).res.getD 5 0)
            ((reduceWordsG n words (n + 1)).res.getD 6 0)
            ((reduceWordsG n words (n + 1)).res.getD 7 0)
            (fromPartialEvalsG ((reduceWordsG n words (n + 1)).res.getD 0 0)
              ((reduceWordsG n words (n + 1)).res.getD 1 0)
              ((reduceWordsG n words (n + 1)).res.getD 2 0)
              ((reduceWordsG n words (n + 1)).res.getD 3 0)
              (reduceWordsG n words (n + 1)).next).next).ops)) := h
  rw [allHold_cons, allHold_append, allHold_append] at h
  obtain ⟨hc, ⟨hrws, hlo⟩, hhi⟩ := h
  simp only [Holds] at hc
  obtain ⟨rlen, rval⟩ := reduceWordsG_sound hc words ws (n + 1) hrw hrws
  have hv : ∀ j, j < 8 →
      ρ ((reduceWordsG n words (n + 1)).res.getD j 0)
        = QM31.fromBase (((ws.getD j 0).toNat : ℕ) : F) := by
    intro j hj
    exact rval j (by omega)
  constructor
  · have e1 := fromPartialEvalsG_sound hlo
    rw [hv 0 (by omega), hv 1 (by omega), hv 2 (by omega),
      hv 3 (by omega)] at e1
    exact e1
  · have e2 := fromPartialEvalsG_sound hhi
    rw [hv 4 (by omega), hv 5 (by omega), hv 6 (by omega),
      hv 7 (by omega)] at e2
    exact e2

/-! ### The felt bytes are the felt words -/

theorem flatten4_getD {α β : Type} [Inhabited α] (g : α → List β) (d : β)
    (hg : ∀ x, (g x).length = 4) :
    ∀ (l : List α) (k c : ℕ), k < l.length → c < 4 →
      ((l.map g).flatten).getD (4 * k + c) d = (g (l.getD k default)).getD c d
  | [], k, c, hk, _ => absurd hk (by simp)
  | x :: rest, k, c, hk, hc => by
    rw [List.map_cons, List.flatten_cons]
    cases k with
    | zero =>
      rw [List.getD_eq_getElem?_getD,
        List.getElem?_append_left (by rw [hg x]; omega),
        ← List.getD_eq_getElem?_getD,
        show 4 * 0 + c = c from by omega]
      rfl
    | succ k =>
      rw [List.getD_eq_getElem?_getD,
        List.getElem?_append_right (by rw [hg x]; omega),
        ← List.getD_eq_getElem?_getD, hg x,
        show 4 * (k + 1) + c - 4 = 4 * k + c from by omega]
      exact flatten4_getD g d hg rest k c (by simpa using hk) hc

theorem flatMap_coords_length (xs : List QM31) :
    (xs.flatMap QM31.coords).length = 4 * xs.length := by
  induction xs with
  | nil => rfl
  | cons x rest ih =>
    rw [List.flatMap_cons, List.length_append, ih,
      show (QM31.coords x).length = 4 from rfl, List.length_cons]
    ring

theorem feltWords_eq_map (xs : List QM31) :
    feltWords xs
      = (xs.flatMap QM31.coords).map fun v => BitVec.ofNat 32 v.val := by
  unfold feltWords
  rw [List.map_flatMap]

theorem bytesFlat (xs : List QM31) :
    (xs.map Channel.qm31Bytes).flatten
      = ((xs.flatMap QM31.coords).map fun v => Channel.u32Le v.val).flatten := by
  induction xs with
  | nil => rfl
  | cons x rest ih =>
    rw [List.map_cons, List.flatten_cons, List.flatMap_cons, List.map_append,
      List.flatten_append, ih]
    rfl

theorem leWord_flatten (xs : List QM31) (k : ℕ) (hk : k < 4 * xs.length) :
    Blake2s.leWord ((xs.map Channel.qm31Bytes).flatten) k
      = (feltWords xs).getD k 0 := by
  rw [bytesFlat, feltWords_eq_map,
    getD_map' _ (0 : Blake2s.Word) (xs.flatMap QM31.coords) k
      (by rw [flatMap_coords_length]; omega)]
  unfold Blake2s.leWord
  have hb : ∀ c, c < 4 →
      (((xs.flatMap QM31.coords).map fun v => Channel.u32Le v.val).flatten).getD
        (4 * k + c) 0
        = (Channel.u32Le ((xs.flatMap QM31.coords).getD k default).val).getD
            c 0 :=
    fun c hc => flatten4_getD _ 0 (fun _ => rfl) (xs.flatMap QM31.coords) k c
      (by rw [flatMap_coords_length]; omega) hc
  rw [show 4 * k = 4 * k + 0 from by omega, hb 0 (by omega)]
  rw [hb 1 (by omega), hb 2 (by omega), hb 3 (by omega)]
  set v := ((xs.flatMap QM31.coords).getD k default).val with hv
  have hvlt : v < 2 ^ 32 :=
    lt_of_lt_of_le (ZMod.val_lt _) (by unfold P; norm_num)
  show BitVec.ofNat 32 ((UInt8.ofNat v).toNat
    + 2 ^ 8 * (UInt8.ofNat (v / 2 ^ 8)).toNat
    + 2 ^ 16 * (UInt8.ofNat (v / 2 ^ 16)).toNat
    + 2 ^ 24 * (UInt8.ofNat (v / 2 ^ 24)).toNat) = BitVec.ofNat 32 v
  refine BitVec.eq_of_toNat_eq ?_
  rw [BitVec.toNat_ofNat, BitVec.toNat_ofNat]
  show ((v % 256 + 2 ^ 8 * (v / 2 ^ 8 % 256) + 2 ^ 16 * (v / 2 ^ 16 % 256)
    + 2 ^ 24 * (v / 2 ^ 24 % 256)) % 2 ^ 32) = v % 2 ^ 32
  omega

/-! ### Padding independence -/

theorem getD_pad (bytes : List UInt8) (z m : ℕ) :
    (bytes ++ List.replicate z 0).getD m 0
      = if m < bytes.length then bytes.getD m 0 else 0 := by
  by_cases hm : m < bytes.length
  · rw [if_pos hm, List.getD_eq_getElem?_getD, List.getElem?_append_left hm,
      ← List.getD_eq_getElem?_getD]
  · rw [if_neg hm]
    push_neg at hm
    by_cases hin : m < bytes.length + z
    · rw [List.getD_eq_getElem?_getD, List.getElem?_append_right hm,
        List.getElem?_replicate, if_pos (by omega)]
      rfl
    · rw [List.getD_eq_default _ _ (by simp; omega)]

theorem leWord_pad_indep (bytes : List UInt8) (z1 z2 k : ℕ) :
    Blake2s.leWord (bytes ++ List.replicate z1 0) k
      = Blake2s.leWord (bytes ++ List.replicate z2 0) k := by
  unfold Blake2s.leWord
  rw [getD_pad, getD_pad, getD_pad, getD_pad, getD_pad, getD_pad, getD_pad,
    getD_pad]

/-! ### The felt-level hash -/

/-- `blake2s` over QM31-packed input: unpack to words, hash. -/
noncomputable def blake2sFeltsG (felts : List ℕ) (nBytes n : ℕ) :
    Out (List ℕ) :=
  let uw := unpackFeltsG felts n
  let hsh := blake2sU32sG uw.res nBytes uw.next
  ⟨uw.ops ++ hsh.ops, hsh.res, hsh.next⟩

set_option maxHeartbeats 1000000 in
/-- **The felt-level hash is the spec hash of the serialized bytes**:
felt registers carrying `xs`, whose byte serialization is `bytes`
zero-padded to the felt boundary (the emitter's precondition), hash to
the digest words of `Blake2s.blake2s bytes`. -/
theorem blake2sFeltsG_sound {ρ : ℕ → QM31} {felts : List ℕ}
    {xs : List QM31} {bytes : List UInt8} {n : ℕ}
    (hfl : felts.length = xs.length)
    (hfv : ∀ i, i < felts.length → ρ (felts.getD i 0) = xs.getD i 0)
    (hbytes : (xs.map Channel.qm31Bytes).flatten
      = bytes ++ List.replicate (16 * xs.length - bytes.length) 0)
    (hexact : xs.length = (bytes.length + 15) / 16)
    (h : AllHold ρ (blake2sFeltsG felts bytes.length n).ops) :
    RegsWords ρ (blake2sFeltsG felts bytes.length n).res
      ((List.range 8).map (Blake2s.hashBlocks Blake2s.h0 0 bytes)) := by
  replace h : AllHold ρ ((unpackFeltsG felts n).ops
      ++ (blake2sU32sG (unpackFeltsG felts n).res bytes.length
          (unpackFeltsG felts n).next).ops) := h
  rw [allHold_append] at h
  obtain ⟨hu, hh⟩ := h
  have hm := unpackFeltsG_sound felts xs n hfl hfv hu
  have hnb : bytes.length ≤ 16 * xs.length := by omega
  have hsound := blake2sU32sG_sound hm
    (by rw [feltWords_length]; omega)
    (by rw [feltWords_length]; omega)
    (fun k hk => by
      rw [feltWords_length] at hk
      rw [← leWord_flatten xs k (by omega), hbytes, leWord_pad_indep]) hh
  exact hsound

/-- `blake2s_m31`: hash, then the two-felt reduced digest. -/
noncomputable def blake2sM31G (felts : List ℕ) (nBytes n : ℕ) :
    Out (ℕ × ℕ) :=
  let hsh := blake2sFeltsG felts nBytes n
  let red := reduceHashValueG hsh.res hsh.next
  ⟨hsh.ops ++ red.ops, red.res, red.next⟩

/-- **`blake2s_m31` produces the channel's two-felt reduced digest** of
the serialized message. -/
theorem blake2sM31G_sound {ρ : ℕ → QM31} {felts : List ℕ}
    {xs : List QM31} {bytes : List UInt8} {n : ℕ}
    (hfl : felts.length = xs.length)
    (hfv : ∀ i, i < felts.length → ρ (felts.getD i 0) = xs.getD i 0)
    (hbytes : (xs.map Channel.qm31Bytes).flatten
      = bytes ++ List.replicate (16 * xs.length - bytes.length) 0)
    (hexact : xs.length = (bytes.length + 15) / 16)
    (h : AllHold ρ (blake2sM31G felts bytes.length n).ops) :
    ρ (blake2sM31G felts bytes.length n).res.1
      = (digestFelts ((List.range 8).map
          (Blake2s.hashBlocks Blake2s.h0 0 bytes))).1 ∧
    ρ (blake2sM31G felts bytes.length n).res.2
      = (digestFelts ((List.range 8).map
          (Blake2s.hashBlocks Blake2s.h0 0 bytes))).2 := by
  replace h : AllHold ρ ((blake2sFeltsG felts bytes.length n).ops
      ++ (reduceHashValueG (blake2sFeltsG felts bytes.length n).res
          (blake2sFeltsG felts bytes.length n).next).ops) := h
  rw [allHold_append] at h
  obtain ⟨hhash, hred⟩ := h
  have hw := blake2sFeltsG_sound hfl hfv hbytes hexact hhash
  exact reduceHashValueG_sound hw (by rw [hw.len]; simp) hred

end StwoVerifier.Gadgets
