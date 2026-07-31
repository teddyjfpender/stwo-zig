import RiscvRefinement.Common

/-!
# Team B publication selector inventory

The twenty-two Team B selectors have one closed identity space.  The
family-specific modules prove the accepted-production-AIR implications; this
module prevents an omitted, duplicated, or renamed selector from being hidden
by an unordered theorem-name list.
-/

namespace RiscvRefinement.Publication.TeamB

inductive Selector where
  | sll
  | srl
  | sra
  | slli
  | srli
  | srai
  | lb
  | lh
  | lw
  | lbu
  | lhu
  | sb
  | sh
  | sw
  | mul
  | mulh
  | mulhsu
  | mulhu
  | div
  | divu
  | rem
  | remu
deriving DecidableEq, Repr

def Selector.manifestId : Selector → Nat
  | .sll => 2
  | .srl => 6
  | .sra => 7
  | .slli => 16
  | .srli => 17
  | .srai => 18
  | .lb => 19
  | .lh => 20
  | .lw => 21
  | .lbu => 22
  | .lhu => 23
  | .sb => 24
  | .sh => 25
  | .sw => 26
  | .mul => 37
  | .mulh => 38
  | .mulhsu => 39
  | .mulhu => 40
  | .div => 41
  | .divu => 42
  | .rem => 43
  | .remu => 44

def Selector.mnemonic : Selector → String
  | .sll => "sll"
  | .srl => "srl"
  | .sra => "sra"
  | .slli => "slli"
  | .srli => "srli"
  | .srai => "srai"
  | .lb => "lb"
  | .lh => "lh"
  | .lw => "lw"
  | .lbu => "lbu"
  | .lhu => "lhu"
  | .sb => "sb"
  | .sh => "sh"
  | .sw => "sw"
  | .mul => "mul"
  | .mulh => "mulh"
  | .mulhsu => "mulhsu"
  | .mulhu => "mulhu"
  | .div => "div"
  | .divu => "divu"
  | .rem => "rem"
  | .remu => "remu"

def Selector.localTheoremIdentity : Selector → String
  | .sll =>
      "RiscvRefinement.Publication.TeamB.Shifts.sll_accepted_air_implies_retirement"
  | .srl =>
      "RiscvRefinement.Publication.TeamB.Shifts.srl_accepted_air_implies_retirement"
  | .sra =>
      "RiscvRefinement.Publication.TeamB.Shifts.sra_accepted_air_implies_retirement"
  | .slli =>
      "RiscvRefinement.Publication.TeamB.Shifts.slli_accepted_air_implies_retirement"
  | .srli =>
      "RiscvRefinement.Publication.TeamB.Shifts.srli_accepted_air_implies_retirement"
  | .srai =>
      "RiscvRefinement.Publication.TeamB.Shifts.srai_accepted_air_implies_retirement"
  | .lb =>
      "RiscvRefinement.Publication.TeamB.LoadStore.lb_accepted_air_implies_retirement"
  | .lh =>
      "RiscvRefinement.Publication.TeamB.LoadStore.lh_accepted_air_implies_retirement"
  | .lw =>
      "RiscvRefinement.Publication.TeamB.LoadStore.lw_accepted_air_implies_retirement"
  | .lbu =>
      "RiscvRefinement.Publication.TeamB.LoadStore.lbu_accepted_air_implies_retirement"
  | .lhu =>
      "RiscvRefinement.Publication.TeamB.LoadStore.lhu_accepted_air_implies_retirement"
  | .sb =>
      "RiscvRefinement.Publication.TeamB.LoadStore.sb_accepted_air_implies_retirement"
  | .sh =>
      "RiscvRefinement.Publication.TeamB.LoadStore.sh_accepted_air_implies_retirement"
  | .sw =>
      "RiscvRefinement.Publication.TeamB.LoadStore.sw_accepted_air_implies_retirement"
  | .mul =>
      "RiscvRefinement.Publication.TeamB.Multiply.mul_accepted_air_implies_retirement"
  | .mulh =>
      "RiscvRefinement.Publication.TeamB.MulhDiv.mulh_accepted_air_implies_retirement"
  | .mulhsu =>
      "RiscvRefinement.Publication.TeamB.MulhDiv.mulhsu_accepted_air_implies_retirement"
  | .mulhu =>
      "RiscvRefinement.Publication.TeamB.MulhDiv.mulhu_accepted_air_implies_retirement"
  | .div =>
      "RiscvRefinement.Publication.TeamB.MulhDiv.div_accepted_air_implies_retirement"
  | .divu =>
      "RiscvRefinement.Publication.TeamB.MulhDiv.divu_accepted_air_implies_retirement"
  | .rem =>
      "RiscvRefinement.Publication.TeamB.MulhDiv.rem_accepted_air_implies_retirement"
  | .remu =>
      "RiscvRefinement.Publication.TeamB.MulhDiv.remu_accepted_air_implies_retirement"

def Selector.sailTheoremIdentity : Selector → String
  | .sll => "LeanRV32IM.Functions.complete_SLL_normalizes"
  | .srl => "LeanRV32IM.Functions.complete_SRL_normalizes"
  | .sra => "LeanRV32IM.Functions.complete_SRA_normalizes"
  | .slli => "LeanRV32IM.Functions.complete_SLLI_normalizes"
  | .srli => "LeanRV32IM.Functions.complete_SRLI_normalizes"
  | .srai => "LeanRV32IM.Functions.complete_SRAI_normalizes"
  | .lb => "LeanRV32IM.Functions.complete_LB_normalizes"
  | .lh => "LeanRV32IM.Functions.complete_LH_normalizes"
  | .lw => "LeanRV32IM.Functions.complete_LW_normalizes"
  | .lbu => "LeanRV32IM.Functions.complete_LBU_normalizes"
  | .lhu => "LeanRV32IM.Functions.complete_LHU_normalizes"
  | .sb => "LeanRV32IM.Functions.complete_SB_normalizes"
  | .sh => "LeanRV32IM.Functions.complete_SH_normalizes"
  | .sw => "LeanRV32IM.Functions.complete_SW_normalizes"
  | .mul => "LeanRV32IM.Functions.complete_MUL_normalizes"
  | .mulh => "LeanRV32IM.Functions.complete_MULH_normalizes"
  | .mulhsu => "LeanRV32IM.Functions.complete_MULHSU_normalizes"
  | .mulhu => "LeanRV32IM.Functions.complete_MULHU_normalizes"
  | .div => "LeanRV32IM.Functions.complete_DIV_normalizes"
  | .divu => "LeanRV32IM.Functions.complete_DIVU_normalizes"
  | .rem => "LeanRV32IM.Functions.complete_REM_normalizes"
  | .remu => "LeanRV32IM.Functions.complete_REMU_normalizes"

def selectors : List Selector := [
  .sll, .srl, .sra, .slli, .srli, .srai,
  .lb, .lh, .lw, .lbu, .lhu, .sb, .sh, .sw,
  .mul, .mulh, .mulhsu, .mulhu, .div, .divu, .rem, .remu
]

def manifestIds : List Nat :=
  selectors.map Selector.manifestId

def mnemonics : List String :=
  selectors.map Selector.mnemonic

def localTheoremIdentities : List String :=
  selectors.map Selector.localTheoremIdentity

def externalSailTheoremIdentities : List String :=
  selectors.map Selector.sailTheoremIdentity

theorem Selector.manifestId_injective :
    Function.Injective Selector.manifestId := by
  intro left right equality
  cases left <;> cases right <;>
    simp_all [Selector.manifestId]

theorem selectors_length : selectors.length = 22 := by decide

theorem selectors_nodup : selectors.Nodup := by decide

theorem manifestIds_exact :
    manifestIds =
      [2, 6, 7, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26,
        37, 38, 39, 40, 41, 42, 43, 44] := by
  rfl

theorem manifestIds_length : manifestIds.length = 22 := by decide

theorem manifestIds_nodup : manifestIds.Nodup := by decide

theorem mnemonics_length : mnemonics.length = 22 := by decide

theorem mnemonics_nodup : mnemonics.Nodup := by decide

theorem localTheoremIdentities_length :
    localTheoremIdentities.length = 22 := by decide

theorem localTheoremIdentities_nodup :
    localTheoremIdentities.Nodup := by decide

theorem externalSailTheoremIdentities_length :
    externalSailTheoremIdentities.length = 22 := by decide

theorem externalSailTheoremIdentities_nodup :
    externalSailTheoremIdentities.Nodup := by decide

end RiscvRefinement.Publication.TeamB
