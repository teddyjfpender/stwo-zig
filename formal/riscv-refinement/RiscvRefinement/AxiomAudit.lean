import RiscvRefinement.Coverage

#print axioms RiscvRefinement.WordBytes.value_lt
#print axioms RiscvRefinement.WordBytes.word_toNat
#print axioms RiscvRefinement.WordBytes.zero_word
#print axioms RiscvRefinement.WordBytes.eq_of_limbs
#print axioms RiscvRefinement.toNat_append_arith
#print axioms RiscvRefinement.architecturalWrite_zero
#print axioms RiscvRefinement.architecturalValue_zero
#print axioms RiscvRefinement.architecturalWrite_value
#print axioms RiscvRefinement.Decode.encode_lui_is_canonical
#print axioms RiscvRefinement.Decode.encode_addi_is_canonical
#print axioms RiscvRefinement.Opcodes.lui_value_refines
#print axioms RiscvRefinement.Opcodes.lui_result_bytes_refine
#print axioms RiscvRefinement.Opcodes.lui_destination_from_constraints
#print axioms RiscvRefinement.Opcodes.lui_refines
#print axioms RiscvRefinement.Opcodes.addi_immediate_refines
#print axioms RiscvRefinement.Opcodes.addi_immediate_value_lt
#print axioms RiscvRefinement.Opcodes.addi_source_from_constraints
#print axioms RiscvRefinement.Opcodes.addi_arithmetic_from_constraints
#print axioms RiscvRefinement.Opcodes.addi_destination_from_constraints
#print axioms RiscvRefinement.Opcodes.addi_value_refines
#print axioms RiscvRefinement.Opcodes.addi_refines
#print axioms RiscvRefinement.NonVacuity.honest_lui_holds
#print axioms RiscvRefinement.NonVacuity.lui_exists
#print axioms RiscvRefinement.NonVacuity.honest_addi_holds
#print axioms RiscvRefinement.NonVacuity.addi_exists
#print axioms RiscvRefinement.Coverage.pilot_coverage_exact
