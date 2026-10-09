import S31.Gadgets.Composition
import S31.Gadgets.Word
import S31.Semantics.Poseidon2
import S31.Semantics.Blake2s
import S31.Semantics.Sha256

namespace S31.Gadgets.Hash
open Graph

def fieldPrimitive (op : FieldOp) (args : List M31) (y : M31) : Prop :=
  match op with
  | .add => y - (args.getD 0 0 + args.getD 1 0) = 0
  | .mul => y - (args.getD 0 0 * args.getD 1 0) = 0

theorem field_primitive_sound_complete (op : FieldOp) (args : List M31) (y : M31) :
    fieldPrimitive op args y ↔ y = fieldEval op args := by
  cases op <;> exact RiscvRefinement.M31.sub_eq_zero_iff _ _

/-- Reuse the existing arbitrary-witness S-box proof, including its canonical
mod-p interpretation; no duplicate M31 implementation is introduced. -/
theorem sbox_sound_complete (x square fifth : M31) :
    RiscvRefinement.Recursion.CompactPoseidon.accepts x square fifth ↔
      square = x * x ∧ fifth = RiscvRefinement.Recursion.CompactPoseidon.fifthPower x := by
  constructor
  · intro h
    exact ⟨(RiscvRefinement.M31.sub_eq_zero_iff _ _).mp h.1,
      RiscvRefinement.Recursion.CompactPoseidon.accepted_output _ _ _ h⟩
  · rintro ⟨rfl, h⟩
    rw [← RiscvRefinement.Recursion.CompactPoseidon.lowered_eq_fifthPower] at h
    rw [h]
    exact RiscvRefinement.Recursion.CompactPoseidon.honest_witness x

theorem field_schedule_sound_complete (code : Code M31 FieldOp) (inputs output : List M31) :
    code.accepts fieldPrimitive inputs output ↔ output = code.eval fieldEval inputs :=
  code_sound_complete code fieldEval fieldPrimitive field_primitive_sound_complete inputs output

theorem word_schedule_sound_complete (code : Code Words.Word WordOp)
    (inputs output : List Words.Word) :
    code.accepts Word.primitive inputs output ↔ output = code.eval wordEval inputs :=
  code_sound_complete code wordEval Word.primitive Word.primitive_sound_complete inputs output

theorem poseidon_leaf_sound_complete (inputs output : List M31) :
    (Poseidon2.leafCode inputs.length).accepts fieldPrimitive inputs output ↔
      output = Poseidon2.leaf inputs := field_schedule_sound_complete _ _ _

theorem poseidon_pair_sound_complete (left right output : List M31) :
    Poseidon2.pairCode.accepts fieldPrimitive (left ++ right) output ↔
      output = Poseidon2.pair left right := field_schedule_sound_complete _ _ _

theorem blake_compression_sound_complete (length : Nat) (personalization : List Nat)
    (inputs output : List Words.Word) :
    (Blake2s.code length personalization).accepts Word.primitive inputs output ↔
      output = (Blake2s.code length personalization).eval wordEval inputs :=
  word_schedule_sound_complete _ _ _

theorem sha_compression_sound_complete (state block output : List Words.Word) :
    Sha256.compressionCode.accepts Word.primitive (state ++ block) output ↔
      output = Sha256.compress state block := word_schedule_sound_complete _ _ _

end S31.Gadgets.Hash
