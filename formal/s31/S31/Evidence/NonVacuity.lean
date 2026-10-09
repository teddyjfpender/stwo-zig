import S31.Gadgets

namespace S31.Evidence
open Gadgets

theorem honest_byte_boundary : Radix.byteConstraint 255 (255*256) :=
  Radix.byte_complete _ (by decide)

theorem byte_out_of_range : ¬∃ scaled, Radix.byteConstraint 256 scaled := by
  rw [Radix.byte_sound_complete]
  decide

theorem honest_carry : Radix.addConstraint 65536 65535 1 0 0 1 := by
  unfold Radix.addConstraint; decide
theorem honest_borrow : Radix.subConstraint 65536 0 1 0 65535 1 := by
  unfold Radix.subConstraint; decide

theorem checked_overflow_rejected : ¬Radix.AddChain 65536 [65535] [1] [0] 0 0 := by
  intro h
  have heq := Radix.add_chain_equation (Or.inr rfl) h
  norm_num [Words.decode] at heq

theorem checked_underflow_rejected : ¬Radix.SubChain 65536 [0] [1] [65535] 0 0 := by
  intro h
  have heq := Radix.sub_chain_equation (Or.inr rfl) h
  norm_num [Words.decode] at heq

theorem zero_inverse_witness_free (w : Field.F) : zeroConstraint 0 1 w := by simp [zeroConstraint]

theorem nonboolean_rejected : ¬bit (2 : Field.F) := by unfold bit; decide
theorem illegal_selector_rejected : ¬selectConstraint (2 : Field.F) 0 0 0 := by
  unfold selectConstraint bit; decide

theorem signed_positive_overflow :
    ¬Signed.addOverflow (encodeBool false) (encodeBool false) (encodeBool true) := by
  rw [Signed.add_overflow_sound_complete]
  decide

theorem signed_negative_overflow :
    ¬Signed.addOverflow (encodeBool true) (encodeBool true) (encodeBool false) := by
  rw [Signed.add_overflow_sound_complete]
  decide

theorem signed_subtraction_overflow :
    ¬Signed.subOverflow (encodeBool true) (encodeBool false) (encodeBool false) := by
  rw [Signed.sub_overflow_sound_complete]
  decide

theorem negative_interpretation : Signed.twos 128 128 = -128 := rfl

theorem honest_division : Bitcoin.divisionConstraint 100 7 14 2 := by
  unfold Bitcoin.divisionConstraint; decide
theorem wrong_quotient_rejected : ¬Bitcoin.divisionConstraint 100 7 13 2 := by
  unfold Bitcoin.divisionConstraint; decide
theorem oversized_remainder_rejected : ¬Bitcoin.divisionConstraint 100 7 13 9 := by
  unfold Bitcoin.divisionConstraint; decide

theorem high_product_not_truncated : ¬Schoolbook.Columns [256] [0] 0 0 := by
  intro h
  have heq := Schoolbook.columns_equation h
  norm_num [Words.decode] at heq

theorem terminal_carry_is_necessary : Schoolbook.Columns [256] [0] 0 1 := by
  exact .cons (by unfold Schoolbook.columnConstraint; decide) (.nil (by decide))

theorem invalid_exponent_rejected : ¬∃ selectors, Bitcoin.exponentConstraint 33 selectors := by
  rw [Bitcoin.exponent_sound_complete]
  decide

theorem honest_exponent : ∃ selectors, Bitcoin.exponentConstraint 29 selectors :=
  Bitcoin.exponent_complete 29 (by decide) (by decide)

theorem digest_last_word : RiscvRefinement.M31.reduce (2^32 - 1) = 1 := by decide

theorem honest_field_hash_gate :
    Graph.Code.accepts (⟨[.apply .add [0,1]], [2]⟩ : Graph.Code M31 Graph.FieldOp)
      Hash.fieldPrimitive [RiscvRefinement.M31.reduce 2, RiscvRefinement.M31.reduce 3]
      [RiscvRefinement.M31.reduce 5] := by
  apply (Hash.field_schedule_sound_complete _ _ _).mpr
  rfl

theorem forged_field_hash_gate :
    ¬Graph.Code.accepts (⟨[.apply .add [0,1]], [2]⟩ : Graph.Code M31 Graph.FieldOp)
      Hash.fieldPrimitive [RiscvRefinement.M31.reduce 2, RiscvRefinement.M31.reduce 3]
      [RiscvRefinement.M31.reduce 6] := by
  rw [Hash.field_schedule_sound_complete]
  decide

/-- This counterexample documents why source-bound widths are a premise of
the public padding theorem. The assignment checker rejects a width change. -/
theorem padding_requires_widths : Bindings.pad8 [1] = Bindings.pad8 [1,0] := by decide

end S31.Evidence
