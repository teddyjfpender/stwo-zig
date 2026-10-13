/-
**The in-circuit channel state** (`stark_verifier/channel.zig`,
stwo-zig `4afa09dbf`).

The circuit keeps the Fiat-Shamir digest as two QM31 wires holding the
eight reduced hash words; the spec keeps 32 digest bytes. `ChDigest`
is the correspondence — the wires' byte serialization is the spec
digest — and it is preserved by the mixes: `blake2s_m31`'s two-felt
result serializes to exactly `chHash true` of the hashed bytes
(`digestFelts_bytes`), because the spec's m31 digest reduction is the
word-wise `mod P` the reduce gadget computes.
-/
import StwoVerifier.BlakePack

namespace StwoVerifier.Gadgets

open StwoVerifier StwoVerifier.Gates

/-! ### The spec's digest reduction, word-wise -/

theorem reduceWord_mod {w : ℕ} (hw : w < 2 ^ 32) :
    Channel.reduceWord w = w % P := by
  unfold Channel.reduceWord P
  show (if w % 2 ^ 31 + w / 2 ^ 31 ≥ 2 ^ 31 - 1
    then w % 2 ^ 31 + w / 2 ^ 31 - (2 ^ 31 - 1)
    else w % 2 ^ 31 + w / 2 ^ 31) = w % (2 ^ 31 - 1)
  by_cases hge : w % 2 ^ 31 + w / 2 ^ 31 ≥ 2 ^ 31 - 1
  · rw [if_pos hge]
    omega
  · rw [if_neg hge]
    omega

theorem reduceWord_lt {w : ℕ} (hw : w < 2 ^ 32) :
    Channel.reduceWord w < P := by
  rw [reduceWord_mod hw]
  exact Nat.mod_lt _ (by unfold P; norm_num)

/-- `wordAt` inverts `digest`'s serialization. -/
theorem wordAt_digest (hf : ℕ → Blake2s.Word) {j : ℕ} (hj : j < 8) :
    Channel.wordAt (Blake2s.digest hf) j = (hf j).toNat := by
  unfold Blake2s.digest Channel.wordAt
  rw [show (List.range 8).flatMap (fun i => (List.range 4).map fun jj =>
      UInt8.ofNat ((hf i).toNat / 2 ^ (8 * jj)))
    = ((List.range 8).map fun i => (List.range 4).map fun jj =>
      UInt8.ofNat ((hf i).toNat / 2 ^ (8 * jj))).flatten from rfl]
  have hb : ∀ c, c < 4 →
      (((List.range 8).map fun i => (List.range 4).map fun jj =>
        UInt8.ofNat ((hf i).toNat / 2 ^ (8 * jj))).flatten).getD (4 * j + c) 0
        = UInt8.ofNat ((hf ((List.range 8).getD j default)).toNat
            / 2 ^ (8 * c)) := by
    intro c hc
    rw [flatten4_getD _ 0 (fun _ => by simp) (List.range 8) j c
      (by simpa using hj) hc]
    rw [getD_map' _ (0 : UInt8) (List.range 4) c (by simpa using hc),
      show (List.range 4).getD c default = c from by
        rw [List.getD_eq_getElem?_getD, List.getElem?_range hc]; rfl]
  have hrj : (List.range 8).getD j default = j := by
    rw [List.getD_eq_getElem?_getD, List.getElem?_range hj]
    rfl
  rw [show 4 * j = 4 * j + 0 from by omega, hb 0 (by omega), hb 1 (by omega),
    hb 2 (by omega), hb 3 (by omega), hrj]
  have hlt := (hf j).isLt
  show ((hf j).toNat / 2 ^ (8 * 0)) % 256
      + 2 ^ 8 * (((hf j).toNat / 2 ^ (8 * 1)) % 256)
      + 2 ^ 16 * (((hf j).toNat / 2 ^ (8 * 2)) % 256)
      + 2 ^ 24 * (((hf j).toNat / 2 ^ (8 * 3)) % 256) = (hf j).toNat
  omega

/-- `wordAt` inverts a run of eight `u32Le` blocks. -/
theorem wordAt_flat_u32Le (g : ℕ → ℕ) (hg : ∀ k, k < 8 → g k < 2 ^ 32)
    {j : ℕ} (hj : j < 8) :
    Channel.wordAt ((List.range 8).flatMap fun k => Channel.u32Le (g k)) j
      = g j := by
  unfold Channel.wordAt
  rw [show (List.range 8).flatMap (fun k => Channel.u32Le (g k))
    = ((List.range 8).map fun k => Channel.u32Le (g k)).flatten from rfl]
  have hb : ∀ c, c < 4 →
      (((List.range 8).map fun k => Channel.u32Le (g k)).flatten).getD
        (4 * j + c) 0
        = (Channel.u32Le (g ((List.range 8).getD j default))).getD c 0 :=
    fun c hc => flatten4_getD _ 0 (fun _ => rfl) (List.range 8) j c
      (by simpa using hj) hc
  have hrj : (List.range 8).getD j default = j := by
    rw [List.getD_eq_getElem?_getD, List.getElem?_range hj]
    rfl
  rw [show 4 * j = 4 * j + 0 from by omega, hb 0 (by omega), hb 1 (by omega),
    hb 2 (by omega), hb 3 (by omega), hrj]
  have hlt := hg j hj
  show g j % 256 + 2 ^ 8 * (g j / 2 ^ 8 % 256) + 2 ^ 16 * (g j / 2 ^ 16 % 256)
      + 2 ^ 24 * (g j / 2 ^ 24 % 256) = g j
  omega

/-- Every `wordAt` is a `u32`. -/
theorem wordAt_lt (b : Channel.Bytes) (j : ℕ) :
    Channel.wordAt b j < 2 ^ 32 := by
  unfold Channel.wordAt
  have h0 := (b.getD (4 * j) 0).toNat_lt
  have h1 := (b.getD (4 * j + 1) 0).toNat_lt
  have h2 := (b.getD (4 * j + 2) 0).toNat_lt
  have h3 := (b.getD (4 * j + 3) 0).toNat_lt
  omega

/-- `wordAt` inverts `reduceDigest`'s serialization. -/
theorem wordAt_reduceDigest (b : Channel.Bytes) {j : ℕ} (hj : j < 8) :
    Channel.wordAt (Channel.reduceDigest b) j
      = Channel.reduceWord (Channel.wordAt b j) := by
  unfold Channel.reduceDigest
  exact wordAt_flat_u32Le (fun k => Channel.reduceWord (Channel.wordAt b k))
    (fun k _ => lt_of_lt_of_le (reduceWord_lt (wordAt_lt b k))
      (by unfold P; norm_num)) hj

/-! ### The two-felt digest serializes to the spec digest -/

theorem fromPartialEvals_base (a b c d : F) :
    fromPartialEvals [QM31.fromBase a, QM31.fromBase b,
      QM31.fromBase c, QM31.fromBase d] = ⟨⟨a, b⟩, ⟨c, d⟩⟩ := by
  unfold fromPartialEvals
  simp only [List.getD_cons_zero, List.getD_cons_succ]
  refine QM31.ext' ?_ ?_ <;>
    (ext <;>
      simp [QM31.fromBase, CM31.fromBase, QM31.fromM31s, QM31.mul_c0,
        QM31.mul_c1, QM31.add_c0, QM31.add_c1, QM31.R, CM31.mul_a, CM31.mul_b,
        CM31.add_a, CM31.add_b] <;> ring)

theorem qm31Bytes_mk (a b c d : F) :
    Channel.qm31Bytes ⟨⟨a, b⟩, ⟨c, d⟩⟩
      = Channel.u32Le a.val ++ Channel.u32Le b.val
        ++ Channel.u32Le c.val ++ Channel.u32Le d.val := by
  unfold Channel.qm31Bytes QM31.coords Channel.feltBytes
  simp [List.flatten]

/-- **The reduce gadget's two felts serialize to the spec's m31
digest** of the same hash. -/
theorem digestFelts_bytes (bytes : List UInt8) :
    Channel.qm31Bytes (digestFelts ((List.range 8).map
        (Blake2s.hashBlocks Blake2s.h0 0 bytes))).1
      ++ Channel.qm31Bytes (digestFelts ((List.range 8).map
        (Blake2s.hashBlocks Blake2s.h0 0 bytes))).2
      = Channel.chHash true bytes := by
  have hget : ∀ j, j < 8 →
      ((List.range 8).map (Blake2s.hashBlocks Blake2s.h0 0 bytes)).getD j 0
        = Blake2s.hashBlocks Blake2s.h0 0 bytes j := by
    intro j hj
    rw [getD_map' _ (0 : Blake2s.Word) (List.range 8) j (by simpa using hj),
      show (List.range 8).getD j default = j from by
        rw [List.getD_eq_getElem?_getD, List.getElem?_range hj]; rfl]
  have hword : ∀ j, j < 8 →
      Channel.reduceWord (Channel.wordAt (Blake2s.blake2s bytes) j)
        = (Blake2s.hashBlocks Blake2s.h0 0 bytes j).toNat % P := by
    intro j hj
    unfold Blake2s.blake2s
    rw [wordAt_digest _ hj,
      reduceWord_mod (Blake2s.hashBlocks Blake2s.h0 0 bytes j).isLt]
  have hval : ∀ j, j < 8 →
      (((((List.range 8).map (Blake2s.hashBlocks Blake2s.h0 0 bytes)).getD
        j 0).toNat : ℕ) : F).val
        = Channel.reduceWord (Channel.wordAt (Blake2s.blake2s bytes) j) := by
    intro j hj
    rw [hget j hj, hword j hj, ZMod.val_natCast]
  unfold digestFelts
  rw [show (List.range 4).map (fun j => QM31.fromBase
      (((((List.range 8).map (Blake2s.hashBlocks Blake2s.h0 0 bytes)).getD
        j 0).toNat : ℕ) : F))
      = [QM31.fromBase _, QM31.fromBase _, QM31.fromBase _, QM31.fromBase _]
    from rfl]
  rw [show (List.range 4).map (fun j => QM31.fromBase
      (((((List.range 8).map (Blake2s.hashBlocks Blake2s.h0 0 bytes)).getD
        (4 + j) 0).toNat : ℕ) : F))
      = [QM31.fromBase _, QM31.fromBase _, QM31.fromBase _, QM31.fromBase _]
    from rfl]
  rw [fromPartialEvals_base, fromPartialEvals_base, qm31Bytes_mk,
    qm31Bytes_mk]
  simp only [Nat.reduceAdd, Nat.add_zero]
  rw [hval 0 (by omega), hval 1 (by omega), hval 2 (by omega),
    hval 3 (by omega), hval 4 (by omega), hval 5 (by omega),
    hval 6 (by omega), hval 7 (by omega)]
  unfold Channel.chHash
  rw [if_pos rfl]
  unfold Channel.reduceDigest
  rw [show (List.range 8) = [0, 1, 2, 3, 4, 5, 6, 7] from rfl]
  simp only [List.flatMap_cons, List.flatMap_nil, List.append_nil]
  simp [List.append_assoc]

/-! ### The channel-state correspondence and the mixes -/

/-- The circuit digest wires serialize to the spec digest. -/
def ChDigest (ρ : ℕ → QM31) (low high : ℕ) (d : Channel.Bytes) : Prop :=
  Channel.qm31Bytes (ρ low) ++ Channel.qm31Bytes (ρ high) = d

/-- `mix_qm31s`: `blake2s_m31(digest ‖ values)`. -/
noncomputable def mixQm31sG (low high : ℕ) (values : List ℕ) (n : ℕ) :
    Out (ℕ × ℕ) :=
  blake2sM31G (low :: high :: values) (16 * (2 + values.length)) n

/-- **`mix_qm31s` is `mixFelts`**: the new digest wires serialize to
the spec's post-mix digest. -/
theorem mixQm31sG_sound {ρ : ℕ → QM31} {low high : ℕ} {values : List ℕ}
    {xs : List QM31} {s : Channel.St} {n : ℕ}
    (hd : ChDigest ρ low high s.digest) (hdlen : s.digest.length = 32)
    (hvl : values.length = xs.length)
    (hvv : ∀ i, i < values.length → ρ (values.getD i 0) = xs.getD i 0)
    (h : AllHold ρ (mixQm31sG low high values n).ops) :
    ChDigest ρ (mixQm31sG low high values n).res.1
      (mixQm31sG low high values n).res.2
      (Channel.mixFelts true s xs).digest := by
  have hblen : (s.digest ++ (xs.map Channel.qm31Bytes).flatten).length
      = 16 * (2 + xs.length) := by
    rw [List.length_append, hdlen, List.length_flatten]
    rw [List.map_map, show (List.length ∘ Channel.qm31Bytes) = fun _ => 16
      from funext fun x => rfl]
    simp
    ring
  have hnb : (16 : ℕ) * (2 + values.length)
      = (s.digest ++ (xs.map Channel.qm31Bytes).flatten).length := by
    rw [hblen, hvl]
  replace h : AllHold ρ (blake2sM31G (low :: high :: values)
      (16 * (2 + values.length)) n).ops := h
  rw [hnb] at h
  show Channel.qm31Bytes (ρ (blake2sM31G (low :: high :: values)
      (16 * (2 + values.length)) n).res.1)
    ++ Channel.qm31Bytes (ρ (blake2sM31G (low :: high :: values)
      (16 * (2 + values.length)) n).res.2)
    = (Channel.mixFelts true s xs).digest
  rw [hnb]
  have hsound := blake2sM31G_sound (xs := ρ low :: ρ high :: xs)
    (bytes := s.digest ++ (xs.map Channel.qm31Bytes).flatten)
    (by simp [hvl])
    (fun i hi => by
      match i, hi with
      | 0, _ => rfl
      | 1, _ => rfl
      | (j + 2), hj =>
        show ρ (values.getD j 0) = xs.getD j 0
        exact hvv j (by simpa using hj))
    (by
      rw [List.map_cons, List.map_cons, List.flatten_cons, List.flatten_cons]
      have hcnt : 16 * (ρ low :: ρ high :: xs).length
          - (s.digest ++ (xs.map Channel.qm31Bytes).flatten).length = 0 := by
        rw [hblen, List.length_cons, List.length_cons]
        omega
      rw [hcnt, List.replicate_zero, List.append_nil, ← List.append_assoc,
        hd])
    (by
      rw [hblen, List.length_cons, List.length_cons]
      omega)
    h
  obtain ⟨h1, h2⟩ := hsound
  rw [h1, h2, digestFelts_bytes]
  rfl

/-! ### Drawing -/

/-- The hash word at `j` of the m31 channel hash. -/
theorem chHash_wordAt (bytes : List UInt8) {j : ℕ} (hj : j < 8) :
    Channel.wordAt (Channel.chHash true bytes) j
      = (Blake2s.hashBlocks Blake2s.h0 0 bytes j).toNat % P := by
  unfold Channel.chHash
  rw [if_pos rfl, wordAt_reduceDigest _ hj]
  unfold Blake2s.blake2s
  rw [wordAt_digest _ hj,
    reduceWord_mod (Blake2s.hashBlocks Blake2s.h0 0 bytes j).isLt]

/-- In m31 mode the first draw always lands: every reduced word is
below `2P`. -/
theorem drawBaseFelts_m31 (fuel : ℕ) (hf : 1 ≤ fuel) (s : Channel.St) :
    Channel.drawBaseFelts true fuel s
      = some ([((Channel.wordAt (Channel.chHash true
            (s.digest ++ Channel.u32Le s.nDraws ++ [0])) 0 : ℕ) : F),
          ((Channel.wordAt (Channel.chHash true
            (s.digest ++ Channel.u32Le s.nDraws ++ [0])) 1 : ℕ) : F),
          ((Channel.wordAt (Channel.chHash true
            (s.digest ++ Channel.u32Le s.nDraws ++ [0])) 2 : ℕ) : F),
          ((Channel.wordAt (Channel.chHash true
            (s.digest ++ Channel.u32Le s.nDraws ++ [0])) 3 : ℕ) : F),
          ((Channel.wordAt (Channel.chHash true
            (s.digest ++ Channel.u32Le s.nDraws ++ [0])) 4 : ℕ) : F),
          ((Channel.wordAt (Channel.chHash true
            (s.digest ++ Channel.u32Le s.nDraws ++ [0])) 5 : ℕ) : F),
          ((Channel.wordAt (Channel.chHash true
            (s.digest ++ Channel.u32Le s.nDraws ++ [0])) 6 : ℕ) : F),
          ((Channel.wordAt (Channel.chHash true
            (s.digest ++ Channel.u32Le s.nDraws ++ [0])) 7 : ℕ) : F)],
          ⟨s.digest, s.nDraws + 1⟩) := by
  cases fuel with
  | zero => omega
  | succ fuel =>
    have hall : (Channel.digestWords (Channel.chHash true
        (s.digest ++ Channel.u32Le s.nDraws ++ [0]))).all
        (fun w => decide (w < 2 * P)) = true := by
      rw [List.all_eq_true]
      intro w hw
      obtain ⟨k, hk, rfl⟩ := List.mem_map.mp hw
      refine decide_eq_true ?_
      rw [chHash_wordAt _ (by simpa using (List.mem_range.mp hk))]
      unfold P
      omega
    rw [show Channel.drawBaseFelts true (fuel + 1) s
      = (if ((Channel.digestWords (Channel.chHash true
            (s.digest ++ Channel.u32Le s.nDraws ++ [0]))).all
            fun w => decide (w < 2 * P)) = true
        then some ((Channel.digestWords (Channel.chHash true
            (s.digest ++ Channel.u32Le s.nDraws ++ [0]))).map
            (fun w => ((w : ℕ) : F)),
          (⟨s.digest, s.nDraws + 1⟩ : Channel.St))
        else Channel.drawBaseFelts true fuel
          ⟨s.digest, s.nDraws + 1⟩) from rfl, if_pos hall]
    rfl

set_option maxHeartbeats 4000000 in
/-- `draw_secure_felts 2` in m31 mode: the eight reduced words of one
hash, four per felt, counter bumped. -/
theorem drawSecureFelts_two (s : Channel.St) :
    Channel.drawSecureFelts true 2 s
      = some ([QM31.fromM31s
          ((Channel.wordAt (Channel.chHash true
            (s.digest ++ Channel.u32Le s.nDraws ++ [0])) 0 : ℕ) : F)
          ((Channel.wordAt (Channel.chHash true
            (s.digest ++ Channel.u32Le s.nDraws ++ [0])) 1 : ℕ) : F)
          ((Channel.wordAt (Channel.chHash true
            (s.digest ++ Channel.u32Le s.nDraws ++ [0])) 2 : ℕ) : F)
          ((Channel.wordAt (Channel.chHash true
            (s.digest ++ Channel.u32Le s.nDraws ++ [0])) 3 : ℕ) : F),
          QM31.fromM31s
          ((Channel.wordAt (Channel.chHash true
            (s.digest ++ Channel.u32Le s.nDraws ++ [0])) 4 : ℕ) : F)
          ((Channel.wordAt (Channel.chHash true
            (s.digest ++ Channel.u32Le s.nDraws ++ [0])) 5 : ℕ) : F)
          ((Channel.wordAt (Channel.chHash true
            (s.digest ++ Channel.u32Le s.nDraws ++ [0])) 6 : ℕ) : F)
          ((Channel.wordAt (Channel.chHash true
            (s.digest ++ Channel.u32Le s.nDraws ++ [0])) 7 : ℕ) : F)],
          ⟨s.digest, s.nDraws + 1⟩) := by
  unfold Channel.drawSecureFelts
  show Channel.drawSecureFelts.go true 2 s [] = _
  rw [Channel.drawSecureFelts.go, drawBaseFelts_m31 Channel.drawFuel
    (by unfold Channel.drawFuel; omega) s]
  simp only [Option.bind_eq_bind, Option.bind_some]
  rw [if_neg (show ¬((1 : ℕ) = 0) from by omega),
    show (1 : ℕ) - 1 = 0 from rfl, Channel.drawSecureFelts.go]
  rfl

set_option maxHeartbeats 1000000 in
/-- The two-felt digest, word by word. -/
theorem digestFelts_fromM31s (bytes : List UInt8) :
    (digestFelts ((List.range 8).map
        (Blake2s.hashBlocks Blake2s.h0 0 bytes))).1
      = QM31.fromM31s
          ((Channel.wordAt (Channel.chHash true bytes) 0 : ℕ) : F)
          ((Channel.wordAt (Channel.chHash true bytes) 1 : ℕ) : F)
          ((Channel.wordAt (Channel.chHash true bytes) 2 : ℕ) : F)
          ((Channel.wordAt (Channel.chHash true bytes) 3 : ℕ) : F) ∧
    (digestFelts ((List.range 8).map
        (Blake2s.hashBlocks Blake2s.h0 0 bytes))).2
      = QM31.fromM31s
          ((Channel.wordAt (Channel.chHash true bytes) 4 : ℕ) : F)
          ((Channel.wordAt (Channel.chHash true bytes) 5 : ℕ) : F)
          ((Channel.wordAt (Channel.chHash true bytes) 6 : ℕ) : F)
          ((Channel.wordAt (Channel.chHash true bytes) 7 : ℕ) : F) := by
  have hw : ∀ j, j < 8 →
      ((Channel.wordAt (Channel.chHash true bytes) j : ℕ) : F)
        = ((((List.range 8).map (Blake2s.hashBlocks Blake2s.h0 0
            bytes)).getD j 0).toNat : F) := by
    intro j hj
    rw [chHash_wordAt _ hj, ZMod.natCast_mod,
      getD_map' _ (0 : Blake2s.Word) (List.range 8) j (by simpa using hj),
      show (List.range 8).getD j default = j from by
        rw [List.getD_eq_getElem?_getD, List.getElem?_range hj]; rfl]
  constructor
  · rw [hw 0 (by omega), hw 1 (by omega), hw 2 (by omega), hw 3 (by omega)]
    unfold digestFelts
    rw [show (List.range 4).map (fun j => QM31.fromBase
        (((((List.range 8).map (Blake2s.hashBlocks Blake2s.h0 0
          bytes)).getD j 0).toNat : ℕ) : F))
      = [QM31.fromBase _, QM31.fromBase _, QM31.fromBase _, QM31.fromBase _]
      from rfl, fromPartialEvals_base]
    rfl
  · rw [hw 4 (by omega), hw 5 (by omega), hw 6 (by omega), hw 7 (by omega)]
    unfold digestFelts
    rw [show (List.range 4).map (fun j => QM31.fromBase
        (((((List.range 8).map (Blake2s.hashBlocks Blake2s.h0 0
          bytes)).getD (4 + j) 0).toNat : ℕ) : F))
      = [QM31.fromBase _, QM31.fromBase _, QM31.fromBase _, QM31.fromBase _]
      from rfl, fromPartialEvals_base]
    rfl

/-- `draw_two_qm31s`: the counter constant, then
`blake2s_m31(digest ‖ n_draws ‖ 0)` over 37 bytes. -/
noncomputable def drawTwoQm31sG (low high nDraws n : ℕ) : Out (ℕ × ℕ) :=
  let hsh := blake2sM31G [low, high, n] 37 (n + 1)
  ⟨.const n (QM31.fromM31s ((nDraws : ℕ) : F) 0 0 0) :: hsh.ops,
   hsh.res, hsh.next⟩

set_option maxHeartbeats 2000000 in
/-- **`draw_two_qm31s` draws the spec's two felts**: the result wires
hold exactly `drawSecureFelts true 2`'s values, and the spec state
advances to the bumped counter with the digest unchanged. -/
theorem drawTwoQm31sG_sound {ρ : ℕ → QM31} {low high n : ℕ}
    {s : Channel.St}
    (hd : ChDigest ρ low high s.digest) (hdlen : s.digest.length = 32)
    (hnd : s.nDraws < P)
    (h : AllHold ρ (drawTwoQm31sG low high s.nDraws n).ops) :
    Channel.drawSecureFelts true 2 s
      = some ([ρ (drawTwoQm31sG low high s.nDraws n).res.1,
               ρ (drawTwoQm31sG low high s.nDraws n).res.2],
              ⟨s.digest, s.nDraws + 1⟩) := by
  replace h : AllHold ρ
      (Op.const n (QM31.fromM31s ((s.nDraws : ℕ) : F) 0 0 0) ::
        (blake2sM31G [low, high, n] 37 (n + 1)).ops) := h
  rw [allHold_cons] at h
  obtain ⟨hc, hh⟩ := h
  simp only [Holds] at hc
  have hblen : (s.digest ++ Channel.u32Le s.nDraws ++ [0]).length = 37 := by
    rw [List.length_append, List.length_append, hdlen]
    rfl
  rw [show (37 : ℕ)
    = (s.digest ++ Channel.u32Le s.nDraws ++ [0]).length from hblen.symm] at hh
  have hsound := blake2sM31G_sound
    (xs := [ρ low, ρ high, QM31.fromM31s ((s.nDraws : ℕ) : F) 0 0 0])
    (bytes := s.digest ++ Channel.u32Le s.nDraws ++ [0])
    (by simp)
    (fun i hi => by
      match i, hi with
      | 0, _ => rfl
      | 1, _ => rfl
      | 2, _ => exact hc)
    (by
      rw [show ([ρ low, ρ high,
          QM31.fromM31s ((s.nDraws : ℕ) : F) 0 0 0].map
          Channel.qm31Bytes).flatten
        = Channel.qm31Bytes (ρ low) ++ (Channel.qm31Bytes (ρ high)
          ++ Channel.qm31Bytes
            (QM31.fromM31s ((s.nDraws : ℕ) : F) 0 0 0)) from by
        simp [List.flatten]]
      rw [show Channel.qm31Bytes (QM31.fromM31s ((s.nDraws : ℕ) : F) 0 0 0)
        = Channel.u32Le s.nDraws ++ List.replicate 12 0 from by
        rw [show QM31.fromM31s ((s.nDraws : ℕ) : F) 0 0 0
          = (⟨⟨((s.nDraws : ℕ) : F), 0⟩, ⟨0, 0⟩⟩ : QM31) from rfl,
          qm31Bytes_mk, ZMod.val_cast_of_lt hnd]
        rfl]
      rw [hblen]
      rw [show (16 * ([ρ low, ρ high,
          QM31.fromM31s ((s.nDraws : ℕ) : F) 0 0 0]).length - 37) = 11
        from rfl]
      rw [← List.append_assoc, hd]
      rw [List.append_assoc, List.append_assoc]
      refine congrArg _ ?_
      rw [← List.append_assoc]
      rfl)
    (by rw [hblen]; rfl)
    hh
  obtain ⟨h1, h2⟩ := hsound
  rw [hblen] at h1 h2
  rw [drawSecureFelts_two s]
  show _ = some ([ρ (blake2sM31G [low, high, n] 37 (n + 1)).res.1,
      ρ (blake2sM31G [low, high, n] 37 (n + 1)).res.2],
    (⟨s.digest, s.nDraws + 1⟩ : Channel.St))
  rw [h1, h2, (digestFelts_fromM31s
    (s.digest ++ Channel.u32Le s.nDraws ++ [0])).1,
    (digestFelts_fromM31s (s.digest ++ Channel.u32Le s.nDraws ++ [0])).2]

/-! ### `mix_u32s` / `mix_commitment` -/

theorem leWord_append_left {a b : List UInt8} {k : ℕ}
    (h : 4 * k + 4 ≤ a.length) :
    Blake2s.leWord (a ++ b) k = Blake2s.leWord a k := by
  unfold Blake2s.leWord
  have hg : ∀ m, m < a.length → (a ++ b).getD m 0 = a.getD m 0 := by
    intro m hm
    rw [List.getD_eq_getElem?_getD, List.getElem?_append_left hm,
      ← List.getD_eq_getElem?_getD]
  rw [hg _ (by omega), hg _ (by omega), hg _ (by omega), hg _ (by omega)]

theorem leWord_append_right {a b : List UInt8} {k j : ℕ}
    (h : a.length = 4 * k) :
    Blake2s.leWord (a ++ b) (k + j) = Blake2s.leWord b j := by
  unfold Blake2s.leWord
  have hg : ∀ m, (a ++ b).getD (a.length + m) 0 = b.getD m 0 := by
    intro m
    rw [List.getD_eq_getElem?_getD, List.getElem?_append_right (by omega),
      show a.length + m - a.length = m from by omega,
      ← List.getD_eq_getElem?_getD]
  rw [show 4 * (k + j) = a.length + 4 * j from by omega,
    show a.length + 4 * j + 1 = a.length + (4 * j + 1) from by omega,
    show a.length + 4 * j + 2 = a.length + (4 * j + 2) from by omega,
    show a.length + 4 * j + 3 = a.length + (4 * j + 3) from by omega,
    show a.length + 4 * j = a.length + (4 * j) from rfl,
    hg, hg, hg, hg]

theorem leWord_flat_u32Le (vals : List ℕ) (pad : List UInt8)
    (hv : ∀ v ∈ vals, v < 2 ^ 32) {k : ℕ} (hk : k < vals.length) :
    Blake2s.leWord ((vals.map Channel.u32Le).flatten ++ pad) k
      = BitVec.ofNat 32 (vals.getD k 0) := by
  have hflen : ((vals.map Channel.u32Le).flatten).length = 4 * vals.length := by
    rw [List.length_flatten, List.map_map,
      show (List.length ∘ Channel.u32Le) = fun _ => 4
        from funext fun _ => rfl]
    simp [Nat.mul_comm]
  rw [leWord_append_left (by omega)]
  unfold Blake2s.leWord
  have hb : ∀ c, c < 4 →
      ((vals.map Channel.u32Le).flatten).getD (4 * k + c) 0
        = (Channel.u32Le (vals.getD k default)).getD c 0 :=
    fun c hc => flatten4_getD _ 0 (fun _ => rfl) vals k c hk hc
  rw [show 4 * k = 4 * k + 0 from by omega, hb 0 (by omega), hb 1 (by omega),
    hb 2 (by omega), hb 3 (by omega)]
  have hvk : vals.getD k default < 2 ^ 32 := by
    refine hv _ ?_
    rw [List.getD_eq_getElem?_getD, List.getElem?_eq_getElem hk]
    exact List.getElem_mem hk
  refine BitVec.eq_of_toNat_eq ?_
  rw [BitVec.toNat_ofNat]
  show (vals.getD k default % 256
    + 2 ^ 8 * (vals.getD k default / 2 ^ 8 % 256)
    + 2 ^ 16 * (vals.getD k default / 2 ^ 16 % 256)
    + 2 ^ 24 * (vals.getD k default / 2 ^ 24 % 256)) % 2 ^ 32
    = vals.getD k default % 2 ^ 32
  omega

theorem regsWords_append {ρ : ℕ → QM31} {r1 r2 : List ℕ}
    {w1 w2 : List Blake2s.Word}
    (h1 : RegsWords ρ r1 w1) (h2 : RegsWords ρ r2 w2) :
    RegsWords ρ (r1 ++ r2) (w1 ++ w2) := by
  refine ⟨by rw [List.length_append, List.length_append, h1.len, h2.len],
    fun j hj => ?_⟩
  rw [List.length_append] at hj
  by_cases hjl : j < r1.length
  · rw [List.getD_eq_getElem?_getD, List.getElem?_append_left hjl,
      ← List.getD_eq_getElem?_getD,
      List.getD_eq_getElem?_getD (l := w1 ++ w2),
      List.getElem?_append_left (by rw [← h1.len]; exact hjl),
      ← List.getD_eq_getElem?_getD]
    exact h1.val j hjl
  · push_neg at hjl
    rw [List.getD_eq_getElem?_getD, List.getElem?_append_right hjl,
      ← List.getD_eq_getElem?_getD,
      List.getD_eq_getElem?_getD (l := w1 ++ w2),
      List.getElem?_append_right (by rw [← h1.len]; exact hjl),
      ← List.getD_eq_getElem?_getD, ← h1.len]
    exact h2.val (j - r1.length) (by omega)

/-- `mix_u32s`: the digest unpacked to words, the values appended, one
plain-Blake2s compression, the reduced digest. -/
noncomputable def mixU32sG (low high : ℕ) (values : List ℕ) (n : ℕ) :
    Out (ℕ × ℕ) :=
  let dw := unpackFeltsG [low, high] n
  let hsh := blake2sU32sG (dw.res ++ values) (4 * (8 + values.length)) dw.next
  let red := reduceHashValueG hsh.res hsh.next
  ⟨dw.ops ++ hsh.ops ++ red.ops, red.res, red.next⟩

set_option maxHeartbeats 1000000 in
/-- **`mix_u32s` is the spec's `mixU32s`**: with the value registers
carrying `u32` words `ws`, the new digest wires serialize to
`chHash true (digest ‖ LE(ws))` — `mixRoot` is the eight-word case. -/
theorem mixU32sG_sound {ρ : ℕ → QM31} {low high : ℕ} {values : List ℕ}
    {ws : List ℕ} {s : Channel.St} {n : ℕ}
    (hd : ChDigest ρ low high s.digest) (hdlen : s.digest.length = 32)
    (hws : ∀ w ∈ ws, w < 2 ^ 32)
    (hvr : RegsWords ρ values (ws.map (BitVec.ofNat 32)))
    (hwl : ws.length = values.length)
    (h : AllHold ρ (mixU32sG low high values n).ops) :
    ChDigest ρ (mixU32sG low high values n).res.1
      (mixU32sG low high values n).res.2
      (Channel.mixU32s true s ws).digest := by
  replace h : AllHold ρ ((unpackFeltsG [low, high] n).ops
      ++ (blake2sU32sG ((unpackFeltsG [low, high] n).res ++ values)
          (4 * (8 + values.length)) (unpackFeltsG [low, high] n).next).ops
      ++ (reduceHashValueG (blake2sU32sG
          ((unpackFeltsG [low, high] n).res ++ values)
          (4 * (8 + values.length)) (unpackFeltsG [low, high] n).next).res
          (blake2sU32sG ((unpackFeltsG [low, high] n).res ++ values)
            (4 * (8 + values.length))
            (unpackFeltsG [low, high] n).next).next).ops) := h
  rw [allHold_append, allHold_append] at h
  obtain ⟨⟨hdw, hhash⟩, hred⟩ := h
  have hdwrw := unpackFeltsG_sound [low, high] [ρ low, ρ high] n rfl
    (fun i hi => by
      match i, hi with
      | 0, _ => rfl
      | 1, _ => rfl) hdw
  have hmsg := regsWords_append hdwrw hvr
  set bytes := s.digest ++ (ws.map Channel.u32Le).flatten with hbytes
  have hblen : bytes.length = 4 * (8 + ws.length) := by
    rw [hbytes, List.length_append, hdlen, List.length_flatten,
      List.map_map, show (List.length ∘ Channel.u32Le) = fun _ => 4
        from funext fun _ => rfl]
    simp
    ring
  have hfwlen : (feltWords [ρ low, ρ high]).length = 8 := by
    rw [feltWords_length]
    rfl
  have hmlen : (feltWords [ρ low, ρ high]
      ++ ws.map (BitVec.ofNat 32)).length = 8 + ws.length := by
    rw [List.length_append, hfwlen, List.length_map]
  have hdbytes : ([ρ low, ρ high].map Channel.qm31Bytes).flatten
      = s.digest := by
    rw [show ([ρ low, ρ high].map Channel.qm31Bytes).flatten
      = Channel.qm31Bytes (ρ low) ++ Channel.qm31Bytes (ρ high) from by
        simp [List.flatten], hd]
  have hnb : 4 * (8 + values.length) = bytes.length := by rw [hblen, hwl]
  have hsound := blake2sU32sG_sound (bytes := bytes) hmsg
    (by rw [hmlen, hblen])
    (by rw [hmlen, hblen]; omega)
    (fun k hk => by
      rw [hmlen] at hk
      rw [hbytes, ← hdbytes, List.append_assoc]
      by_cases hk8 : k < 8
      · rw [List.getD_eq_getElem?_getD,
          List.getElem?_append_left (by rw [hfwlen]; omega),
          ← List.getD_eq_getElem?_getD,
          leWord_append_left (by rw [hdbytes, hdlen]; omega),
          leWord_flatten [ρ low, ρ high] k (by simp; omega)]
      · obtain ⟨j, rfl⟩ : ∃ j, k = 8 + j := ⟨k - 8, by omega⟩
        rw [List.getD_eq_getElem?_getD,
          List.getElem?_append_right (by rw [hfwlen]; omega),
          ← List.getD_eq_getElem?_getD, hfwlen, Nat.add_sub_cancel_left,
          getD_map' _ (0 : Blake2s.Word) ws j (by omega),
          leWord_append_right (by rw [hdbytes, hdlen]),
          leWord_flat_u32Le ws _ hws (by omega)]
        rfl)
    (by rw [← hnb]; exact hhash)
  obtain ⟨h1, h2⟩ := reduceHashValueG_sound hsound
    (by rw [hsound.len]; simp) (by rw [← hnb]; exact hred)
  rw [hnb] at h1 h2
  show Channel.qm31Bytes (ρ (reduceHashValueG (blake2sU32sG
      ((unpackFeltsG [low, high] n).res ++ values) (4 * (8 + values.length))
      (unpackFeltsG [low, high] n).next).res (blake2sU32sG
      ((unpackFeltsG [low, high] n).res ++ values) (4 * (8 + values.length))
      (unpackFeltsG [low, high] n).next).next).res.1)
    ++ Channel.qm31Bytes (ρ (reduceHashValueG (blake2sU32sG
      ((unpackFeltsG [low, high] n).res ++ values) (4 * (8 + values.length))
      (unpackFeltsG [low, high] n).next).res (blake2sU32sG
      ((unpackFeltsG [low, high] n).res ++ values) (4 * (8 + values.length))
      (unpackFeltsG [low, high] n).next).next).res.2)
    = Channel.chHash true bytes
  rw [hnb, h1, h2, digestFelts_bytes]

/-- `u32Le` of a `wordAt` gives back the bytes. -/
theorem u32Le_wordAt (b : Channel.Bytes) (k c : ℕ) (hc : c < 4) :
    (Channel.u32Le (Channel.wordAt b k)).getD c 0 = b.getD (4 * k + c) 0 := by
  have h0 := (b.getD (4 * k) 0).toNat_lt
  have h1 := (b.getD (4 * k + 1) 0).toNat_lt
  have h2 := (b.getD (4 * k + 2) 0).toNat_lt
  have h3 := (b.getD (4 * k + 3) 0).toNat_lt
  apply UInt8.toNat_inj.mp
  unfold Channel.u32Le Channel.wordAt
  interval_cases c <;> (try simp only [Nat.add_zero]) <;>
  generalize (b.getD (4 * k) 0).toNat = a0 at *
  <;> generalize (b.getD (4 * k + 1) 0).toNat = a1 at *
  <;> generalize (b.getD (4 * k + 2) 0).toNat = a2 at *
  <;> generalize (b.getD (4 * k + 3) 0).toNat = a3 at *
  · show (a0 + 2 ^ 8 * a1 + 2 ^ 16 * a2 + 2 ^ 24 * a3) % 256 = a0
    omega
  · show (a0 + 2 ^ 8 * a1 + 2 ^ 16 * a2 + 2 ^ 24 * a3) / 2 ^ 8 % 256 = a1
    omega
  · show (a0 + 2 ^ 8 * a1 + 2 ^ 16 * a2 + 2 ^ 24 * a3) / 2 ^ 16 % 256 = a2
    omega
  · show (a0 + 2 ^ 8 * a1 + 2 ^ 16 * a2 + 2 ^ 24 * a3) / 2 ^ 24 % 256 = a3
    omega

/-- A 32-byte root is the serialization of its eight words. -/
theorem root_reconstruct (root : Channel.Bytes) (h32 : root.length = 32) :
    ((Channel.digestWords root).map Channel.u32Le).flatten = root := by
  have hlen : ((Channel.digestWords root).map Channel.u32Le).flatten.length
      = 32 := by
    simp only [Channel.digestWords, List.map_map, List.length_flatten]
    rfl
  refine List.ext_getElem (by rw [hlen, h32]) fun m hm1 hm2 => ?_
  have hm : m < 32 := by omega
  have key : ((Channel.digestWords root).map Channel.u32Le).flatten.getD m 0
      = root.getD m 0 := by
    rw [show m = 4 * (m / 4) + m % 4 from (Nat.div_add_mod' m 4).symm.trans
      (by ring)]
    rw [flatten4_getD _ 0 (fun _ => rfl) (Channel.digestWords root) (m / 4)
      (m % 4) (by simp [Channel.digestWords]; omega) (Nat.mod_lt _ (by omega))]
    unfold Channel.digestWords
    rw [getD_map' _ (default : ℕ) (List.range 8) (m / 4) (by simp; omega),
      show (List.range 8).getD (m / 4) default = m / 4 from by
        rw [List.getD_eq_getElem?_getD, List.getElem?_range (by omega)]; rfl,
      u32Le_wordAt _ _ _ (Nat.mod_lt _ (by omega))]
  rw [List.getD_eq_getElem?_getD, List.getElem?_eq_getElem hm1,
    List.getD_eq_getElem?_getD, List.getElem?_eq_getElem hm2] at key
  simpa using key

/-- `mix_commitment`: `mix_u32s` of the root's eight word wires. -/
noncomputable def mixCommitmentG (low high : ℕ) (rootRegs : List ℕ) (n : ℕ) :
    Out (ℕ × ℕ) :=
  mixU32sG low high rootRegs n

/-- **`mix_commitment` is the spec's `mixRoot`**. -/
theorem mixCommitmentG_sound {ρ : ℕ → QM31} {low high : ℕ}
    {rootRegs : List ℕ} {root : Channel.Bytes} {s : Channel.St} {n : ℕ}
    (hd : ChDigest ρ low high s.digest) (hdlen : s.digest.length = 32)
    (h32 : root.length = 32)
    (hrr : RegsWords ρ rootRegs
      ((Channel.digestWords root).map (BitVec.ofNat 32)))
    (h : AllHold ρ (mixCommitmentG low high rootRegs n).ops) :
    ChDigest ρ (mixCommitmentG low high rootRegs n).res.1
      (mixCommitmentG low high rootRegs n).res.2
      (Channel.mixRoot true s root).digest := by
  have hm := mixU32sG_sound hd hdlen
    (fun w hw => by
      obtain ⟨k, -, rfl⟩ := List.mem_map.mp hw
      exact wordAt_lt root k)
    hrr (by rw [hrr.len, List.length_map]) h
  unfold ChDigest at hm ⊢
  show Channel.qm31Bytes (ρ (mixU32sG low high rootRegs n).res.1) ++
    Channel.qm31Bytes (ρ (mixU32sG low high rootRegs n).res.2) = _
  rw [hm]
  show Channel.chHash true (s.digest ++ _) = Channel.chHash true (s.digest ++ root)
  rw [root_reconstruct root h32]

end StwoVerifier.Gadgets