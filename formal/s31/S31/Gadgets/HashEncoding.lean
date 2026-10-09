import S31.Gadgets.Hash
import S31.Gadgets.Sequence
import S31.Gadgets.Packing

namespace S31.Gadgets.HashEncoding
open Graph Words

def BlakeAccepts (inputs output : List M31) (personalization : List Nat) : Prop :=
  ∃ raw : List Word,
    (Blake2s.code inputs.length personalization).accepts Gadgets.Word.primitive
      (inputs.map (Words.word ∘ (·.val))) raw ∧
    List.Forall₂ (fun x y => Packing.digestReduction x.toNat y) raw output

theorem blake_hash_sound_complete (inputs output : List M31) (personalization : List Nat) :
    BlakeAccepts inputs output personalization ↔ output = Blake2s.hash inputs personalization := by
  have pointwise := Sequence.pointwise_sound_complete
    (fun x : Word => RiscvRefinement.M31.reduce x.toNat)
    (fun x y => Packing.digestReduction x.toNat y)
    (fun x y => Packing.digest_reduction_sound_complete x.toNat y x.isLt)
  constructor
  · rintro ⟨raw, hgraph, hencode⟩
    have heq := (Hash.word_schedule_sound_complete _ _ _).mp hgraph
    have hout := (pointwise raw output).mp hencode
    simpa only [Blake2s.hash, heq, Function.comp_def] using hout
  · intro h
    refine ⟨_, (Hash.word_schedule_sound_complete _ _ _).mpr rfl, ?_⟩
    apply (pointwise _ output).mpr
    simpa only [Blake2s.hash, Function.comp_def] using h

inductive CompressMany : List (List Word) → List Word → List Word → Prop where
  | nil (state) : CompressMany [] state state
  | cons {block blocks state mid output} :
      Sha256.compressionCode.accepts Gadgets.Word.primitive (state ++ block) mid →
      CompressMany blocks mid output → CompressMany (block :: blocks) state output

theorem compress_many_sound {blocks state output} (h : CompressMany blocks state output) :
    output = blocks.foldl Sha256.compress state := by
  induction h with
  | nil => rfl
  | cons hlocal htail ih =>
    have heq := (Hash.sha_compression_sound_complete _ _ _).mp hlocal
    simpa only [List.foldl_cons, heq] using ih

theorem compress_many_complete (blocks : List (List Word)) (state : List Word) :
    CompressMany blocks state (blocks.foldl Sha256.compress state) := by
  induction blocks generalizing state with
  | nil => exact .nil state
  | cons block blocks ih => exact .cons ((Hash.sha_compression_sound_complete _ _ _).mpr rfl) (ih _)

def ShaAccepts (message digest : List Nat) : Prop := ∃ state,
  CompressMany (Sha256.blocks message) (Constants.hashIV.map Words.word) state ∧
    digest = state.flatMap (fun w => Words.bytesBE 4 w.toNat)

theorem sha_hash_sound_complete (message digest : List Nat) :
    ShaAccepts message digest ↔ digest = Sha256.hash message := by
  constructor
  · rintro ⟨state, h, rfl⟩
    rw [compress_many_sound h]
    rfl
  · rintro rfl; exact ⟨_, compress_many_complete _ _, rfl⟩

theorem sha_bytes_bounded (message : List Nat) : Radix.Bounded 256 (Sha256.hash message) := by
  intro byte h
  unfold Sha256.hash at h
  obtain ⟨word, hw, hb⟩ := List.mem_flatMap.mp h
  have hr : byte ∈ encode 256 4 word.toNat := by
    simpa only [Words.bytesBE, Words.bytesLE, List.mem_reverse] using hb
  exact Radix.encode_bounded _ (by decide) _ _ _ hr

theorem getD_bounded (xs : List Nat) (h : Radix.Bounded 256 xs) (i : Nat) : xs.getD i 0 < 256 := by
  induction xs generalizing i with
  | nil => simp
  | cons x xs ih =>
    cases i with
    | zero => exact h x (by simp)
    | succ i => exact ih (fun x hx => h x (by simp [hx])) i

theorem digest_pairs_bounded (message : List Nat) :
    ∀ p ∈ Sha256.digestPairs (Sha256.hash message), p.1 < 256 ∧ p.2 < 256 := by
  intro p hp
  obtain ⟨i, hi, rfl⟩ := List.mem_map.mp hp
  exact ⟨getD_bounded _ (sha_bytes_bounded message) _, getD_bounded _ (sha_bytes_bounded message) _⟩

def HeaderAccepts (limbs output : List M31) : Prop := ∃ first digest,
  ShaAccepts (Words.wordsBytes 2 (limbs.map (·.val))) first ∧ ShaAccepts first digest ∧
    List.Forall₂ (fun p y => Packing.bytePairConstraint p.1 p.2 y.val)
      (Sha256.digestPairs digest) output

theorem header_hash_sound_complete (limbs output : List M31) :
    HeaderAccepts limbs output ↔ output = Sha256.header limbs := by
  let message := Words.wordsBytes 2 (limbs.map (·.val))
  let first := Sha256.hash message
  let digest := Sha256.hash first
  let pairs := Sha256.digestPairs digest
  have bound := digest_pairs_bounded first
  have pointwise : ∀ ps : List (Nat × Nat), (∀ p ∈ ps, p.1 < 256 ∧ p.2 < 256) →
      ∀ out : List M31, List.Forall₂ (fun p y => Packing.bytePairConstraint p.1 p.2 y.val) ps out ↔
        out = ps.map (fun p => RiscvRefinement.M31.reduce (p.1 + 256 * p.2)) := by
    intro ps hb out
    induction ps generalizing out with
    | nil => cases out <;> simp
    | cons p ps ih =>
      cases out with
      | nil => simp
      | cons y ys =>
        have hp := hb p (by simp)
        simp [List.forall₂_cons, Packing.byte_pair_m31_sound_complete _ _ hp.1 hp.2,
          ih (fun p h => hb p (by simp [h])), eq_comm]
  constructor
  · rintro ⟨first', digest', hfirst, hdigest, hout⟩
    have hf : first' = first := (sha_hash_sound_complete _ _).mp hfirst
    subst first'
    have hd : digest' = digest := (sha_hash_sound_complete _ _).mp hdigest
    subst digest'
    exact (pointwise pairs bound output).mp hout
  · intro h
    exact ⟨first, digest, (sha_hash_sound_complete _ _).mpr rfl,
      (sha_hash_sound_complete _ _).mpr rfl, (pointwise pairs bound output).mpr h⟩

end S31.Gadgets.HashEncoding
