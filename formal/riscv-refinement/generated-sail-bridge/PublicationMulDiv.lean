import PublicationMulDivMultiply
import PublicationMulDivHighMultiply
import PublicationMulDivDivision

namespace LeanRV32IM.Publication

theorem MUL_accepted_air_refines : Multiply.RefinementTheorem :=
  Multiply.accepted_air_refines
theorem MULH_accepted_air_refines : HighMultiply.RefinementTheorem .mulh :=
  HighMultiply.accepted_air_refines .mulh
theorem MULHSU_accepted_air_refines : HighMultiply.RefinementTheorem .mulhsu :=
  HighMultiply.accepted_air_refines .mulhsu
theorem MULHU_accepted_air_refines : HighMultiply.RefinementTheorem .mulhu :=
  HighMultiply.accepted_air_refines .mulhu
theorem DIV_accepted_air_refines : Division.RefinementTheorem .div :=
  Division.accepted_air_refines .div
theorem DIVU_accepted_air_refines : Division.RefinementTheorem .divu :=
  Division.accepted_air_refines .divu
theorem REM_accepted_air_refines : Division.RefinementTheorem .rem :=
  Division.accepted_air_refines .rem
theorem REMU_accepted_air_refines : Division.RefinementTheorem .remu :=
  Division.accepted_air_refines .remu

end LeanRV32IM.Publication
