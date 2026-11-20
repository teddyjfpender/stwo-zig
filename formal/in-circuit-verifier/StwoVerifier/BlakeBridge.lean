/-
**The word-level block chain is the byte-level hash** (pure spec side).

`blake2s_u32s` consumes `u32` words padded to whole 64-byte blocks with
the byte counter `min nBytes (64·(i+1))`; the spec `Blake2s.hashBlocks`
consumes bytes 64 at a time, padding only the last block. With the
word list read off the zero-padded bytes (`leWord`), the chains
coincide block by block: the non-last byte counters are `t + 64`, the
last is `nBytes`, and every message-schedule function agrees
everywhere (out-of-range words are zero on both sides).
-/
import StwoVerifier.BlakeGadgets

namespace StwoVerifier.Gadgets

open StwoVerifier StwoVerifier.Gates

/-! ### `leWord` index plumbing -/

theorem getD_drop' {α : Type} (xs : List α) (a m : ℕ) (d : α) :
    (xs.drop a).getD m d = xs.getD (a + m) d := by
  rw [List.getD_eq_getElem?_getD, List.getElem?_drop,
    ← List.getD_eq_getElem?_getD]

theorem leWord_oob {b : List UInt8} {k : ℕ} (h : b.length ≤ 4 * k) :
    Blake2s.leWord b k = 0 := by
  unfold Blake2s.leWord
  rw [List.getD_eq_default _ _ (by omega), List.getD_eq_default _ _ (by omega),
    List.getD_eq_default _ _ (by omega), List.getD_eq_default _ _ (by omega)]
  rfl

theorem leWord_drop (pb : List UInt8) (i l : ℕ) :
    Blake2s.leWord (pb.drop (64 * i)) l = Blake2s.leWord pb (16 * i + l) := by
  unfold Blake2s.leWord
  rw [getD_drop', getD_drop', getD_drop', getD_drop',
    show 64 * i + 4 * l = 4 * (16 * i + l) from by ring,
    show 64 * i + (4 * l + 1) = 4 * (16 * i + l) + 1 from by ring,
    show 64 * i + (4 * l + 2) = 4 * (16 * i + l) + 2 from by ring,
    show 64 * i + (4 * l + 3) = 4 * (16 * i + l) + 3 from by ring]

theorem leWord_take {b : List UInt8} {n k : ℕ} (h : 4 * k + 4 ≤ n) :
    Blake2s.leWord (b.take n) k = Blake2s.leWord b k := by
  unfold Blake2s.leWord
  have ht : ∀ m, m < n → (b.take n).getD m 0 = b.getD m 0 := by
    intro m hm
    rw [List.getD_eq_getElem?_getD, List.getElem?_take, if_pos hm,
      ← List.getD_eq_getElem?_getD]
  rw [ht _ (by omega), ht _ (by omega), ht _ (by omega), ht _ (by omega)]

theorem leWord_replicate_zero (m k : ℕ) :
    Blake2s.leWord (List.replicate m 0) k = 0 := by
  unfold Blake2s.leWord
  have hz : ∀ j, (List.replicate m (0 : UInt8)).getD j 0 = 0 := by
    intro j
    by_cases hj : j < m <;>
      simp [List.getD_eq_getElem?_getD, List.getElem?_replicate, hj]
  rw [hz, hz, hz, hz]
  rfl

/-! ### `hashBlocks` case equations -/

theorem hashBlocks_nil (h : ℕ → Blake2s.Word) (t : ℕ) :
    Blake2s.hashBlocks h t [] = Blake2s.compress h (fun _ => 0) t true := by
  rw [Blake2s.hashBlocks]

theorem hashBlocks_last {b : List UInt8} (hne : b ≠ [])
    (hle : b.length ≤ 64) (h : ℕ → Blake2s.Word) (t : ℕ) :
    Blake2s.hashBlocks h t b
      = Blake2s.compress h
          (Blake2s.leWord (b ++ List.replicate (64 - b.length) 0))
          (t + b.length) true := by
  cases b with
  | nil => exact absurd rfl hne
  | cons x xs =>
    rw [Blake2s.hashBlocks]
    · rw [if_pos (by simpa using hle)]
    · simp

theorem hashBlocks_step {b : List UInt8} (hgt : ¬ b.length ≤ 64)
    (h : ℕ → Blake2s.Word) (t : ℕ) :
    Blake2s.hashBlocks h t b
      = Blake2s.hashBlocks
          (fun i => ((List.range 8).map
            (Blake2s.compress h (Blake2s.leWord (b.take 64)) (t + 64)
              false)).getD i 0)
          (t + 64) (b.drop 64) := by
  cases b with
  | nil => exact absurd (by simp) hgt
  | cons x xs =>
    rw [Blake2s.hashBlocks]
    · rw [if_neg (by simpa using hgt)]
    · simp

/-! ### The message-schedule functions agree -/

/-- The gadget's per-block schedule — the 16-word slice of the padded
word list — is `leWord` of the block's padded bytes, as functions. -/
theorem slice_schedule (bytes : List UInt8) (NB : ℕ)
    (hNB : bytes.length ≤ 64 * NB) (i : ℕ) (hi : i < NB) :
    (fun l => ((((List.range (16 * NB)).map
        (Blake2s.leWord
          (bytes ++ List.replicate (64 * NB - bytes.length) 0))).drop
          (16 * i)).take 16).getD l 0)
      = Blake2s.leWord
          (((bytes ++ List.replicate (64 * NB - bytes.length) 0).drop
            (64 * i)).take 64) := by
  have hpblen : (bytes ++ List.replicate (64 * NB - bytes.length)
      (0 : UInt8)).length = 64 * NB := by
    rw [List.length_append, List.length_replicate]
    omega
  funext l
  by_cases hl : l < 16
  · rw [List.getD_eq_getElem?_getD, List.getElem?_take, if_pos hl,
      List.getElem?_drop, List.getElem?_map,
      List.getElem?_range (by omega : 16 * i + l < 16 * NB)]
    simp only [Option.map_some, Option.getD_some]
    rw [leWord_take (by omega), leWord_drop]
  · rw [List.getD_eq_default _ _ (by
      rw [List.length_take, List.length_drop, List.length_map,
        List.length_range]
      omega)]
    rw [leWord_oob (by
      rw [List.length_take, List.length_drop, hpblen]
      omega)]

/-! ### Padded-chunk equalities -/

theorem chunk_mid {bytes : List UInt8} {NB i : ℕ}
    (hmid : 64 * (i + 1) < bytes.length) :
    ((bytes ++ List.replicate (64 * NB - bytes.length) 0).drop
      (64 * i)).take 64 = (bytes.drop (64 * i)).take 64 := by
  rw [List.drop_append_of_le_length (by omega),
    List.take_append_of_le_length (by rw [List.length_drop]; omega)]

theorem chunk_last {bytes : List UInt8} {NB i : ℕ}
    (hlo : 64 * i < bytes.length) (hhi : bytes.length ≤ 64 * (i + 1))
    (hNBi : NB = i + 1) :
    ((bytes ++ List.replicate (64 * NB - bytes.length) 0).drop
      (64 * i)).take 64
      = bytes.drop (64 * i)
        ++ List.replicate (64 - (bytes.drop (64 * i)).length) 0 := by
  rw [List.drop_append_of_le_length (by omega),
    List.take_append, List.take_replicate, List.length_drop]
  subst hNBi
  rw [show min (64 - (bytes.length - 64 * i)) (64 * (i + 1) - bytes.length)
    = 64 - (bytes.length - 64 * i) from by omega]
  rw [show bytes.drop (64 * i) = (bytes.drop (64 * i)).take 64 from by
    rw [List.take_of_length_le (by rw [List.length_drop]; omega)]]
  rw [List.take_take, min_self]

/-! ### `hashWordsL` equations -/

theorem hashWordsL_zero (ws : List Blake2s.Word) (nB i : ℕ)
    (hl : List Blake2s.Word) : hashWordsL ws nB 0 i hl = hl := rfl

theorem hashWordsL_succ (ws : List Blake2s.Word) (nB k i : ℕ)
    (hl : List Blake2s.Word) :
    hashWordsL ws nB (k + 1) i hl
      = hashWordsL ws nB k (i + 1) ((List.range 8).map fun j =>
          Blake2s.compress (fun l => hl.getD l 0)
            (fun l => ((ws.drop (16 * i)).take 16).getD l 0)
            (min nB ((i + 1) * 64)) (k = 0) j) := rfl

/-! ### The chains coincide -/

/-- **The word chain is the byte chain**: with the word list read off
the zero-padded bytes, `hashWordsL` from block `i` computes
`hashBlocks` on the remaining bytes at byte counter `64·i`. -/
theorem hashWordsL_eq_hashBlocks (bytes : List UInt8) (NB : ℕ)
    (hNB : bytes.length ≤ 64 * NB)
    (hNB2 : ∀ j, j + 1 < NB → 64 * (j + 1) < bytes.length) :
    ∀ (k i : ℕ) (hl : List Blake2s.Word), 1 ≤ k → i + k = NB →
      (64 * i < bytes.length ∨ (i = 0 ∧ bytes.length = 0)) →
      hashWordsL ((List.range (16 * NB)).map
          (Blake2s.leWord
            (bytes ++ List.replicate (64 * NB - bytes.length) 0)))
          bytes.length k i hl
        = (List.range 8).map
            (Blake2s.hashBlocks (fun j => hl.getD j 0) (64 * i)
              (bytes.drop (64 * i)))
  | 0, i, hl, hk, _, _ => absurd hk (by omega)
  | 1, i, hl, _, hik, hpos => by
    rw [hashWordsL_succ, hashWordsL_zero,
      slice_schedule bytes NB hNB i (by omega)]
    rcases hpos with hlo | ⟨hi0, hb0⟩
    · -- The last, nonempty block.
      have hhi : bytes.length ≤ 64 * (i + 1) := by omega
      have hrlen : (bytes.drop (64 * i)).length = bytes.length - 64 * i := by
        rw [List.length_drop]
      rw [chunk_last hlo hhi (by omega),
        hashBlocks_last (by
          intro hnil
          rw [hnil] at hrlen
          simp at hrlen
          omega) (by omega) _ (64 * i)]
      rw [hrlen, show 64 * i + (bytes.length - 64 * i) = bytes.length from by
        omega,
        show min bytes.length ((i + 1) * 64) = bytes.length from by omega]
      rfl
    · -- The empty message: one all-zero block at counter 0.
      subst hi0
      have hbnil : bytes = [] := List.eq_nil_of_length_eq_zero hb0
      subst hbnil
      rw [show List.drop (64 * 0) ([] : List UInt8) = [] from by simp,
        hashBlocks_nil]
      have hm : Blake2s.leWord ((([] : List UInt8) ++
          List.replicate (64 * NB - ([] : List UInt8).length) 0).drop
            (64 * 0) |>.take 64)
          = fun _ => (0 : Blake2s.Word) := by
        funext l
        by_cases hl64 : 4 * l + 4 ≤ 64
        · rw [leWord_take hl64]
          have hrepl : (([] : List UInt8) ++
              List.replicate (64 * NB - ([] : List UInt8).length)
                (0 : UInt8)).drop (64 * 0)
              = List.replicate (64 * NB) (0 : UInt8) := by simp
          rw [hrepl, leWord_replicate_zero]
        · rw [leWord_oob (by rw [List.length_take]; omega)]
      rw [hm, show min ([] : List UInt8).length ((0 + 1) * 64) = 64 * 0
        from by simp]
      rfl
  | k + 2, i, hl, _, hik, hpos => by
    have hmid : 64 * (i + 1) < bytes.length := hNB2 i (by omega)
    rw [hashWordsL_succ,
      slice_schedule bytes NB hNB i (by omega), chunk_mid hmid]
    have hrgt : ¬ (bytes.drop (64 * i)).length ≤ 64 := by
      rw [List.length_drop]
      omega
    rw [hashBlocks_step hrgt, List.drop_drop,
      show 64 * i + 64 = 64 * (i + 1) from by ring]
    rw [hashWordsL_eq_hashBlocks bytes NB hNB hNB2 (k + 1) (i + 1) _
      (by omega) (by omega) (Or.inl hmid)]
    rw [show min bytes.length ((i + 1) * 64) = 64 * (i + 1) from by
      omega,
      show (bytes.drop (64 * i)).take 64 = (bytes.take (64 * (i + 1))).drop
        (64 * i) from by
        rw [List.drop_take]
        congr 1
        omega,
      show decide (k + 1 = 0) = false from by simp]

/-! ### `h`-function congruence (only the eight chaining words matter) -/

theorem initV_congr {h1 h2 : ℕ → Blake2s.Word}
    (hagree : ∀ j, j < 8 → h1 j = h2 j) (t : ℕ) (f : Bool) :
    Blake2s.initV h1 t f = Blake2s.initV h2 t f := by
  unfold Blake2s.initV
  refine List.map_congr_left fun i hi => ?_
  by_cases hi8 : i < 8
  · simp [hi8, hagree i hi8]
  · simp [hi8]

theorem compress_congr {h1 h2 : ℕ → Blake2s.Word}
    (hagree : ∀ j, j < 8 → h1 j = h2 j) (m : ℕ → Blake2s.Word)
    (t : ℕ) (f : Bool) (i : ℕ) (hi : i < 8) :
    Blake2s.compress h1 m t f i = Blake2s.compress h2 m t f i := by
  unfold Blake2s.compress
  rw [initV_congr hagree, hagree i hi]

private theorem hashBlocks_congr' :
    ∀ (N : ℕ) (h1 h2 : ℕ → Blake2s.Word),
      (∀ j, j < 8 → h1 j = h2 j) → ∀ (t : ℕ) (b : List UInt8),
      b.length ≤ N → ∀ i, i < 8 →
      Blake2s.hashBlocks h1 t b i = Blake2s.hashBlocks h2 t b i
  | 0, h1, h2, hagree, t, b, hlen, i, hi => by
    have hb : b = [] := List.eq_nil_of_length_eq_zero (by omega)
    subst hb
    rw [hashBlocks_nil, hashBlocks_nil]
    exact compress_congr hagree _ _ _ i hi
  | N + 1, h1, h2, hagree, t, b, hlen, i, hi => by
    cases hb : b with
    | nil =>
      rw [hashBlocks_nil, hashBlocks_nil]
      exact compress_congr hagree _ _ _ i hi
    | cons x xs =>
      by_cases hle : (x :: xs).length ≤ 64
      · rw [hashBlocks_last (by simp) hle, hashBlocks_last (by simp) hle]
        exact compress_congr hagree _ _ _ i hi
      · rw [hashBlocks_step hle, hashBlocks_step hle]
        refine hashBlocks_congr' N _ _ ?_ (t + 64) ((x :: xs).drop 64)
          (by subst hb; rw [List.length_drop]; simp at hle; omega) i hi
        intro j hj
        rw [getD_map' _ (0 : Blake2s.Word) (List.range 8) j
            (by simpa using hj),
          getD_map' _ (0 : Blake2s.Word) (List.range 8) j
            (by simpa using hj),
          show (List.range 8).getD j default = j from by
            rw [List.getD_eq_getElem?_getD, List.getElem?_range hj]; rfl]
        exact compress_congr hagree _ _ _ j hj

theorem hashBlocks_congr {h1 h2 : ℕ → Blake2s.Word}
    (hagree : ∀ j, j < 8 → h1 j = h2 j) (t : ℕ) (b : List UInt8)
    (i : ℕ) (hi : i < 8) :
    Blake2s.hashBlocks h1 t b i = Blake2s.hashBlocks h2 t b i :=
  hashBlocks_congr' b.length h1 h2 hagree t b (le_refl _) i hi

/-! ### Padded words beyond the message are zero -/

theorem leWord_pad_zero {bytes : List UInt8} {z k : ℕ}
    (h : bytes.length ≤ 4 * k) :
    Blake2s.leWord (bytes ++ List.replicate z 0) k = 0 := by
  unfold Blake2s.leWord
  have hz : ∀ m, bytes.length ≤ m →
      (bytes ++ List.replicate z (0 : UInt8)).getD m 0 = 0 := by
    intro m hm
    by_cases hin : m < bytes.length + z
    · rw [List.getD_eq_getElem?_getD, List.getElem?_append_right hm,
        List.getElem?_replicate, if_pos (by omega)]
      rfl
    · rw [List.getD_eq_default _ _ (by simp; omega)]
  rw [hz _ (by omega), hz _ (by omega), hz _ (by omega), hz _ (by omega)]
  rfl

/-! ### The whole hash -/

/-- `blake2s_u32s`: the zero padding word, the parameterized IV, the
block loop (`builder/blake.zig`). -/
noncomputable def blake2sU32sG (msgRegs : List ℕ) (nBytes : ℕ) (n : ℕ) :
    Out (List ℕ) :=
  let NB := max 1 ((nBytes + 63) / 64)
  let padded := msgRegs ++ List.replicate (16 * NB - msgRegs.length) n
  let hRegs := (List.range 8).map fun i => n + 1 + i
  let blocks := blocksG padded nBytes NB 0 hRegs (n + 9)
  ⟨.const n (packW 0) ::
    (((List.range 8).map fun i => .const (n + 1 + i) (packW (Blake2s.h0 i)))
      ++ blocks.ops), blocks.res, blocks.next⟩

set_option maxHeartbeats 1000000 in
/-- **The in-circuit Blake2s is the spec hash**: message registers
carrying the words of `bytes` (zero-padded in the last word) hash to
registers carrying `Blake2s.hashBlocks h0 0 bytes` — the digest words
of `Blake2s.blake2s bytes`. -/
theorem blake2sU32sG_sound {ρ : ℕ → QM31} {msgRegs : List ℕ}
    {mws : List Blake2s.Word} {bytes : List UInt8} {n : ℕ}
    (hm : RegsWords ρ msgRegs mws)
    (hcover : bytes.length ≤ 4 * mws.length)
    (hfit : mws.length ≤ 16 * max 1 ((bytes.length + 63) / 64))
    (hwords : ∀ k, k < mws.length →
      mws.getD k 0 = Blake2s.leWord (bytes ++
        List.replicate (64 * max 1 ((bytes.length + 63) / 64)
          - bytes.length) 0) k)
    (h : AllHold ρ (blake2sU32sG msgRegs bytes.length n).ops) :
    RegsWords ρ (blake2sU32sG msgRegs bytes.length n).res
      ((List.range 8).map (Blake2s.hashBlocks Blake2s.h0 0 bytes)) := by
  set NB := max 1 ((bytes.length + 63) / 64) with hNBdef
  have hNB : bytes.length ≤ 64 * NB := by
    rw [hNBdef]
    omega
  have hNB2 : ∀ j, j + 1 < NB → 64 * (j + 1) < bytes.length := by
    intro j hj
    rw [hNBdef] at hj
    omega
  replace h : AllHold ρ
      (Op.const n (packW 0) ::
        (((List.range 8).map fun i =>
            Op.const (n + 1 + i) (packW (Blake2s.h0 i))) ++
          (blocksG (msgRegs ++ List.replicate (16 * NB - msgRegs.length) n)
            bytes.length NB 0 ((List.range 8).map fun i => n + 1 + i)
            (n + 9)).ops)) := h
  rw [allHold_cons, allHold_append] at h
  obtain ⟨hzero, hhc, hblocks⟩ := h
  simp only [Holds] at hzero
  -- The padded registers carry the padded words.
  have hpad : RegsWords ρ
      (msgRegs ++ List.replicate (16 * NB - msgRegs.length) n)
      ((List.range (16 * NB)).map (Blake2s.leWord
        (bytes ++ List.replicate (64 * NB - bytes.length) 0))) := by
    have hmlen : msgRegs.length = mws.length := hm.len
    refine ⟨by simp [hmlen]; omega, fun j hj => ?_⟩
    rw [List.length_append, List.length_replicate, hmlen] at hj
    have hj16 : j < 16 * NB := by omega
    rw [getD_map' _ (0 : Blake2s.Word) (List.range (16 * NB)) j
        (by simpa using hj16),
      show (List.range (16 * NB)).getD j default = j from by
        rw [List.getD_eq_getElem?_getD, List.getElem?_range hj16]; rfl]
    by_cases hjm : j < mws.length
    · rw [List.getD_eq_getElem?_getD, List.getElem?_append_left
        (by omega), ← List.getD_eq_getElem?_getD]
      rw [hm.val j (by omega), hwords j hjm]
    · rw [List.getD_eq_getElem?_getD, List.getElem?_append_right
        (by omega), List.getElem?_replicate, if_pos (by omega)]
      simp only [Option.getD_some]
      rw [hzero, leWord_pad_zero (by omega)]
  -- The chaining registers carry `h0`.
  have hh0 : RegsWords ρ ((List.range 8).map fun i => n + 1 + i)
      ((List.range 8).map Blake2s.h0) := by
    refine ⟨by simp, fun j hj => ?_⟩
    rw [List.length_map, List.length_range] at hj
    rw [getD_map' _ (0 : ℕ) (List.range 8) j (by simpa using hj),
      getD_map' _ (0 : Blake2s.Word) (List.range 8) j (by simpa using hj),
      show (List.range 8).getD j default = j from by
        rw [List.getD_eq_getElem?_getD, List.getElem?_range hj]; rfl]
    have hc := hhc (.const (n + 1 + j) (packW (Blake2s.h0 j)))
      (List.mem_map.mpr ⟨j, by simp [hj], rfl⟩)
    simpa [Holds] using hc
  have hbl := blocksG_sound hpad NB 0 _ _ (n + 9) hh0 (by simp)
    (by simp) hblocks
  rw [hashWordsL_eq_hashBlocks bytes NB hNB hNB2 NB 0 _
    (by rw [hNBdef]; omega) (by omega) (by
      rcases Nat.eq_zero_or_pos bytes.length with h0 | h0
      · exact Or.inr ⟨rfl, h0⟩
      · exact Or.inl (by omega))] at hbl
  rw [show (64 * 0 : ℕ) = 0 from rfl, List.drop_zero] at hbl
  refine ⟨?_, fun j hj => ?_⟩
  · show (blocksG (msgRegs ++ List.replicate (16 * NB - msgRegs.length) n)
      bytes.length NB 0 ((List.range 8).map fun i => n + 1 + i)
      (n + 9)).res.length = _
    rw [hbl.len]
    simp
  · have hj' : j < (blocksG (msgRegs ++ List.replicate
        (16 * NB - msgRegs.length) n) bytes.length NB 0
        ((List.range 8).map fun i => n + 1 + i) (n + 9)).res.length := hj
    show ρ ((blocksG (msgRegs ++ List.replicate
      (16 * NB - msgRegs.length) n) bytes.length NB 0
      ((List.range 8).map fun i => n + 1 + i) (n + 9)).res.getD j 0) = _
    rw [hbl.val j hj']
    have hj8 : j < 8 := by
      have := hbl.len
      rw [List.length_map, List.length_range] at this
      omega
    rw [getD_map' _ (0 : Blake2s.Word) (List.range 8) j (by simpa using hj8),
      getD_map' _ (0 : Blake2s.Word) (List.range 8) j (by simpa using hj8),
      show (List.range 8).getD j default = j from by
        rw [List.getD_eq_getElem?_getD, List.getElem?_range hj8]; rfl]
    refine congrArg _ ?_
    refine hashBlocks_congr (fun l hl => ?_) 0 bytes j hj8
    rw [getD_map' _ (0 : Blake2s.Word) (List.range 8) l (by simpa using hl),
      show (List.range 8).getD l default = l from by
        rw [List.getD_eq_getElem?_getD, List.getElem?_range hl]; rfl]

end StwoVerifier.Gadgets
