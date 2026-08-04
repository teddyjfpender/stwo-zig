import PublicationAlu
import PublicationCompare
import PublicationShifts
import PublicationControl
import PublicationMemoryTheorem
import PublicationMulDiv

/-!
# Universal generated-Sail publication contract

This is the single public entrypoint for FV-2.  Its contract carries the
kernel-checked production-AIR-to-generated-Sail composition for every one of
the 46 admitted RV32IM selectors, together with the generated full-step
framing theorem.  The explicit fields make omissions and duplicate coverage
visible to both Lean and the receipt generator.
-/

namespace LeanRV32IM.Publication

/-- Preserve a named proof as a checked field of the universal contract. -/
structure Carries {statement : Prop} (evidence : statement) : Prop where
  checked : statement

/-- Exact FV-2 publication inventory in production manifest order. -/
structure UniversalPublicationContract : Prop where
  add : Carries ADD_accepted_air_refines
  sub : Carries SUB_accepted_air_refines
  sll : Carries SLL_accepted_air_refines
  slt : Carries SLT_accepted_air_refines
  sltu : Carries SLTU_accepted_air_refines
  xor : Carries XOR_accepted_air_refines
  srl : Carries SRL_accepted_air_refines
  sra : Carries SRA_accepted_air_refines
  or : Carries OR_accepted_air_refines
  andOp : Carries AND_accepted_air_refines
  addi : Carries ADDI_accepted_air_refines
  slti : Carries SLTI_accepted_air_refines
  sltiu : Carries SLTIU_accepted_air_refines
  xori : Carries XORI_accepted_air_refines
  ori : Carries ORI_accepted_air_refines
  andi : Carries ANDI_accepted_air_refines
  slli : Carries SLLI_accepted_air_refines
  srli : Carries SRLI_accepted_air_refines
  srai : Carries SRAI_accepted_air_refines
  lb : Carries LB_accepted_air_refines
  lh : Carries LH_accepted_air_refines
  lw : Carries LW_accepted_air_refines
  lbu : Carries LBU_accepted_air_refines
  lhu : Carries LHU_accepted_air_refines
  sb : Carries SB_accepted_air_refines
  sh : Carries SH_accepted_air_refines
  sw : Carries SW_accepted_air_refines
  beq : Carries BEQ_accepted_air_refines
  bne : Carries BNE_accepted_air_refines
  blt : Carries BLT_accepted_air_refines
  bge : Carries BGE_accepted_air_refines
  bltu : Carries BLTU_accepted_air_refines
  bgeu : Carries BGEU_accepted_air_refines
  jal : Carries JAL_accepted_air_refines
  jalr : Carries JALR_accepted_air_refines
  lui : Carries LUI_accepted_air_refines
  auipc : Carries AUIPC_accepted_air_refines
  mul : Carries MUL_accepted_air_refines
  mulh : Carries MULH_accepted_air_refines
  mulhsu : Carries MULHSU_accepted_air_refines
  mulhu : Carries MULHU_accepted_air_refines
  div : Carries DIV_accepted_air_refines
  divu : Carries DIVU_accepted_air_refines
  rem : Carries REM_accepted_air_refines
  remu : Carries REMU_accepted_air_refines
  fence : Carries FENCE_accepted_air_refines
  fullStep : Carries
    LeanRV32IM.Functions.generated_full_step_retirement_composition

/-- One kernel term carrying the complete, ordered FV-2 publication surface. -/
theorem universal_publication_contract : UniversalPublicationContract := {
  add := ⟨ADD_accepted_air_refines⟩
  sub := ⟨SUB_accepted_air_refines⟩
  sll := ⟨SLL_accepted_air_refines⟩
  slt := ⟨SLT_accepted_air_refines⟩
  sltu := ⟨SLTU_accepted_air_refines⟩
  xor := ⟨XOR_accepted_air_refines⟩
  srl := ⟨SRL_accepted_air_refines⟩
  sra := ⟨SRA_accepted_air_refines⟩
  or := ⟨OR_accepted_air_refines⟩
  andOp := ⟨AND_accepted_air_refines⟩
  addi := ⟨ADDI_accepted_air_refines⟩
  slti := ⟨SLTI_accepted_air_refines⟩
  sltiu := ⟨SLTIU_accepted_air_refines⟩
  xori := ⟨XORI_accepted_air_refines⟩
  ori := ⟨ORI_accepted_air_refines⟩
  andi := ⟨ANDI_accepted_air_refines⟩
  slli := ⟨SLLI_accepted_air_refines⟩
  srli := ⟨SRLI_accepted_air_refines⟩
  srai := ⟨SRAI_accepted_air_refines⟩
  lb := ⟨LB_accepted_air_refines⟩
  lh := ⟨LH_accepted_air_refines⟩
  lw := ⟨LW_accepted_air_refines⟩
  lbu := ⟨LBU_accepted_air_refines⟩
  lhu := ⟨LHU_accepted_air_refines⟩
  sb := ⟨SB_accepted_air_refines⟩
  sh := ⟨SH_accepted_air_refines⟩
  sw := ⟨SW_accepted_air_refines⟩
  beq := ⟨BEQ_accepted_air_refines⟩
  bne := ⟨BNE_accepted_air_refines⟩
  blt := ⟨BLT_accepted_air_refines⟩
  bge := ⟨BGE_accepted_air_refines⟩
  bltu := ⟨BLTU_accepted_air_refines⟩
  bgeu := ⟨BGEU_accepted_air_refines⟩
  jal := ⟨JAL_accepted_air_refines⟩
  jalr := ⟨JALR_accepted_air_refines⟩
  lui := ⟨LUI_accepted_air_refines⟩
  auipc := ⟨AUIPC_accepted_air_refines⟩
  mul := ⟨MUL_accepted_air_refines⟩
  mulh := ⟨MULH_accepted_air_refines⟩
  mulhsu := ⟨MULHSU_accepted_air_refines⟩
  mulhu := ⟨MULHU_accepted_air_refines⟩
  div := ⟨DIV_accepted_air_refines⟩
  divu := ⟨DIVU_accepted_air_refines⟩
  rem := ⟨REM_accepted_air_refines⟩
  remu := ⟨REMU_accepted_air_refines⟩
  fence := ⟨FENCE_accepted_air_refines⟩
  fullStep :=
    ⟨LeanRV32IM.Functions.generated_full_step_retirement_composition⟩
}

#print axioms ADD_accepted_air_refines
#print axioms SUB_accepted_air_refines
#print axioms SLL_accepted_air_refines
#print axioms SLT_accepted_air_refines
#print axioms SLTU_accepted_air_refines
#print axioms XOR_accepted_air_refines
#print axioms SRL_accepted_air_refines
#print axioms SRA_accepted_air_refines
#print axioms OR_accepted_air_refines
#print axioms AND_accepted_air_refines
#print axioms ADDI_accepted_air_refines
#print axioms SLTI_accepted_air_refines
#print axioms SLTIU_accepted_air_refines
#print axioms XORI_accepted_air_refines
#print axioms ORI_accepted_air_refines
#print axioms ANDI_accepted_air_refines
#print axioms SLLI_accepted_air_refines
#print axioms SRLI_accepted_air_refines
#print axioms SRAI_accepted_air_refines
#print axioms LB_accepted_air_refines
#print axioms LH_accepted_air_refines
#print axioms LW_accepted_air_refines
#print axioms LBU_accepted_air_refines
#print axioms LHU_accepted_air_refines
#print axioms SB_accepted_air_refines
#print axioms SH_accepted_air_refines
#print axioms SW_accepted_air_refines
#print axioms BEQ_accepted_air_refines
#print axioms BNE_accepted_air_refines
#print axioms BLT_accepted_air_refines
#print axioms BGE_accepted_air_refines
#print axioms BLTU_accepted_air_refines
#print axioms BGEU_accepted_air_refines
#print axioms JAL_accepted_air_refines
#print axioms JALR_accepted_air_refines
#print axioms LUI_accepted_air_refines
#print axioms AUIPC_accepted_air_refines
#print axioms MUL_accepted_air_refines
#print axioms MULH_accepted_air_refines
#print axioms MULHSU_accepted_air_refines
#print axioms MULHU_accepted_air_refines
#print axioms DIV_accepted_air_refines
#print axioms DIVU_accepted_air_refines
#print axioms REM_accepted_air_refines
#print axioms REMU_accepted_air_refines
#print axioms FENCE_accepted_air_refines
#print axioms LeanRV32IM.Functions.generated_full_step_retirement_composition
#print axioms universal_publication_contract

end LeanRV32IM.Publication
