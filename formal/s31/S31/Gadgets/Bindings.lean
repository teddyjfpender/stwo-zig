import S31.Semantics.Program
import S31.Gadgets.Field

namespace S31.Gadgets.Bindings

def values (env : Nat → M31) (wires : List Nat) : List M31 := wires.map env

theorem constant_wires (env : Nat → M31) (wire length : Nat) (value : M31)
    (h : env wire = value) :
    values env (List.replicate length wire) = List.replicate length value := by
  simp [values, h]

theorem cast_wire_identity (env : Nat → M31) (wires : List Nat) :
    values env wires = wires.map env := rfl

theorem array_get_wire (env : Nat → M31) (wires : List Nat) (i : Nat) (hi : i < wires.length) :
    values env [wires[i]] = [(values env wires)[i]'(by simp [values, hi])] := by
  simp [values]

theorem array_concat_wires (env : Nat → M31) (left right : List Nat) :
    values env (left ++ right) = values env left ++ values env right := by
  simp [values]

theorem array_slice_wires (env : Nat → M31) (wires : List Nat) (offset length : Nat) :
    values env ((wires.drop offset).take length) = ((values env wires).drop offset).take length := by
  simp [values, List.map_take, List.map_drop]

def assertion (a b : M31) : Prop := a - b = 0

theorem assertion_sound_complete (a b : M31) : assertion a b ↔ a = b :=
  RiscvRefinement.M31.sub_eq_zero_iff a b

def pad8 (words : List M31) : List M31 := words ++ List.replicate (8 - words.length) 0

theorem padding_length (words : List M31) (h : words.length ≤ 8) : (pad8 words).length = 8 := by
  simp only [pad8, List.length_append, List.length_replicate]
  omega

theorem padding_prefix (words : List M31) : (pad8 words).take words.length = words := by
  simp [pad8]

/-- Widths belong to the source-bound statement. Without the equal-width
premise, trailing zero padding would make [x] and [x,0] indistinguishable. -/
theorem padding_binding (xs ys : List M31) (hwidth : xs.length = ys.length) :
    pad8 xs = pad8 ys ↔ xs = ys := by
  constructor
  · intro h
    have heq := congrArg (List.take xs.length) h
    rw [padding_prefix] at heq
    rw [hwidth, padding_prefix] at heq
    exact heq
  · exact congrArg pad8

theorem segment_binding (xs ys left right : List M31) (hwidth : xs.length = ys.length) :
    xs ++ left = ys ++ right ↔ xs = ys ∧ left = right := by
  constructor
  · intro h; exact List.append_inj h hwidth
  · rintro ⟨rfl, rfl⟩; rfl

theorem proof_mode_validation (p : Program) (mode : ProofMode) :
    {p with proofMode := mode}.validate = p.validate := rfl

theorem proof_mode_claims (p : Program) (mode : ProofMode) (a : Assignment) :
    {p with proofMode := mode}.claimedWords a = p.claimedWords a := rfl

theorem proof_mode_environment (p : Program) (mode : ProofMode) (a : Assignment) :
    {p with proofMode := mode}.environment a = p.environment a := rfl

theorem proof_mode_semantics (p : Program) (mode : ProofMode) (a : Assignment) :
    {p with proofMode := mode}.evaluate a = p.evaluate a := rfl

end S31.Gadgets.Bindings
