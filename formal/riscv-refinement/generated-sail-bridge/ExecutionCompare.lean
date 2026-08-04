import ExecutionClosure
import RiscvRefinement.Opcodes.Lt

set_option maxHeartbeats 1_000_000_000
set_option maxRecDepth 100_000

open Sail

namespace LeanRV32IM.Publication.ExecutionCompare

open RiscvRefinement

private theorem unsignedSemanticLess_eq
    (left right : WordBytes) :
    Air.Bridge.LtReg.semanticLess .unsigned left right =
      decide (left.word.toNat < right.word.toNat) := by
  simp only [
    Air.Bridge.LtReg.semanticLess,
    Air.Bridge.LtReg.topKey,
    ← BitVec.toNat_inj,
    WordBytes.word_toNat,
    WordBytes.value,
  ]
  rw [Bool.eq_iff_iff]
  simp only [decide_eq_true_eq]
  have left0 := left.limb0.isLt
  have left1 := left.limb1.isLt
  have left2 := left.limb2.isLt
  have left3 := left.limb3.isLt
  have right0 := right.limb0.isLt
  have right1 := right.limb1.isLt
  have right2 := right.limb2.isLt
  have right3 := right.limb3.isLt
  simp only [Nat.reducePow] at left0 left1 left2 left3
  simp only [Nat.reducePow] at right0 right1 right2 right3
  omega

private theorem signedSemanticLess_eq
    (left right : WordBytes) :
    Air.Bridge.LtReg.semanticLess .signed left right =
      decide (left.word.toInt < right.word.toInt) := by
  have leftSign :
      2 * left.word.toNat < 2 ^ 32 ↔ left.limb3.toNat < 128 := by
    simp only [WordBytes.word_toNat, WordBytes.value, Nat.reducePow]
    have left0 := left.limb0.isLt
    have left1 := left.limb1.isLt
    have left2 := left.limb2.isLt
    have left3 := left.limb3.isLt
    simp only [Nat.reducePow] at left0 left1 left2 left3
    omega
  have rightSign :
      2 * right.word.toNat < 2 ^ 32 ↔ right.limb3.toNat < 128 := by
    simp only [WordBytes.word_toNat, WordBytes.value, Nat.reducePow]
    have right0 := right.limb0.isLt
    have right1 := right.limb1.isLt
    have right2 := right.limb2.isLt
    have right3 := right.limb3.isLt
    simp only [Nat.reducePow] at right0 right1 right2 right3
    omega
  unfold Air.Bridge.LtReg.semanticLess Air.Bridge.LtReg.topKey
  rw [BitVec.toInt_eq_toNat_cond, BitVec.toInt_eq_toNat_cond]
  simp only [leftSign, rightSign]
  simp only [← BitVec.toNat_inj, WordBytes.word_toNat,
    WordBytes.value, Nat.reducePow]
  by_cases leftNonnegative : left.limb3.toNat < 128 <;>
    by_cases rightNonnegative : right.limb3.toNat < 128 <;>
    simp only [leftNonnegative, rightNonnegative, ↓reduceIte]
  all_goals
    rw [Bool.eq_iff_iff]
    simp only [decide_eq_true_eq]
    have left0 := left.limb0.isLt
    have left1 := left.limb1.isLt
    have left2 := left.limb2.isLt
    have left3 := left.limb3.isLt
    have right0 := right.limb0.isLt
    have right1 := right.limb1.isLt
    have right2 := right.limb2.isLt
    have right3 := right.limb3.isLt
    simp only [Nat.reducePow] at left0 left1 left2 left3
    simp only [Nat.reducePow] at right0 right1 right2 right3
    omega

theorem semanticLess_eq_generated
    (kind : Air.Bridge.LtReg.Kind) (left right : WordBytes) :
    Air.Bridge.LtReg.semanticLess kind left right =
      match kind with
      | .signed => LeanRV32IM.Functions.zopz0zI_s left.word right.word
      | .unsigned => LeanRV32IM.Functions.zopz0zI_u left.word right.word := by
  cases kind
  · simpa [LeanRV32IM.Functions.zopz0zI_s] using
      signedSemanticLess_eq left right
  · simpa [LeanRV32IM.Functions.zopz0zI_u, Sail.BitVec.toNatInt] using
      unsignedSemanticLess_eq left right

private theorem generatedComparisonWord_eq (result : Bool) :
    _root_.zero_extend (m := 32)
        (LeanRV32IM.Functions.bool_to_bit result) =
      (Air.Bridge.LtReg.comparisonBytes result).word := by
  cases result <;> rfl

theorem generatedRegValue_eq_resultWord
    (kind : Air.Bridge.LtReg.Kind) (left right : WordBytes) :
    (match kind with
      | .signed => _root_.zero_extend (m := 32)
          (LeanRV32IM.Functions.bool_to_bit
            (LeanRV32IM.Functions.zopz0zI_s left.word right.word))
      | .unsigned => _root_.zero_extend (m := 32)
          (LeanRV32IM.Functions.bool_to_bit
            (LeanRV32IM.Functions.zopz0zI_u left.word right.word))) =
      (Air.Bridge.LtReg.comparisonBytes
        (Air.Bridge.LtReg.semanticLess kind left right)).word := by
  cases kind <;>
    rw [semanticLess_eq_generated] <;>
    exact generatedComparisonWord_eq _

theorem immediateBytes_word (immediate : BitVec 12) :
    (Air.Bridge.LtImm.immediateBytes immediate).word =
      LeanRV32IM.Functions.sign_extend (m := 32) immediate := by
  let low := Air.Bridge.LtImm.imm0 immediate
  let middle := Air.Bridge.LtImm.imm1 immediate
  let sign := Air.Bridge.LtImm.immMsb immediate
  have reconstruction :
      Air.Generated.addiImmediate low middle sign = immediate := by
    dsimp [low, middle, sign, Air.Generated.addiImmediate,
      Air.Bridge.LtImm.imm0, Air.Bridge.LtImm.imm1,
      Air.Bridge.LtImm.immMsb]
    bv_decide
  have bytesEq :
      (Air.Bridge.LtImm.immediateBytes immediate).word =
        Air.Generated.addiAirImmediate low middle sign := by
    apply BitVec.eq_of_toNat_eq
    simp only [
      WordBytes.word_toNat,
      WordBytes.value,
      Air.Bridge.LtImm.immediateBytes,
      Air.Generated.addiAirImmediate,
      Air.Generated.addiImmediateValue,
      BitVec.toNat_ofNat,
      Nat.reducePow,
    ]
    have lowBound := low.isLt
    have middleBound := middle.isLt
    have signBound := sign.isLt
    simp only [Nat.reducePow] at lowBound middleBound signBound
    have signCases : sign.toNat = 0 ∨ sign.toNat = 1 := by omega
    rcases signCases with signZero | signOne
    · simp [low, middle, sign, Air.Bridge.LtImm.immSign,
        signZero, Nat.mod_eq_of_lt (by omega : middle.toNat < 256)]
      rw [Nat.mod_eq_of_lt (by omega)]
    · simp [low, middle, sign, Air.Bridge.LtImm.immSign,
        signOne,
        Nat.mod_eq_of_lt (by omega : middle.toNat + 248 < 256)]
      rw [Nat.mod_eq_of_lt (by omega)]
  calc
    _ = Air.Generated.addiAirImmediate low middle sign := bytesEq
    _ = BitVec.signExtend 32
        (Air.Generated.addiImmediate low middle sign) :=
      RiscvRefinement.Opcodes.addi_immediate_refines low middle sign
    _ = LeanRV32IM.Functions.sign_extend (m := 32) immediate := by
      rw [reconstruction]
      rfl

theorem generatedImmValue_eq_resultWord
    (kind : Air.Bridge.LtImm.Kind) (source : WordBytes)
    (immediate : BitVec 12) :
    (match kind with
      | .signed => _root_.zero_extend (m := 32)
          (LeanRV32IM.Functions.bool_to_bit
            (LeanRV32IM.Functions.zopz0zI_s source.word
              (LeanRV32IM.Functions.sign_extend (m := 32) immediate)))
      | .unsigned => _root_.zero_extend (m := 32)
          (LeanRV32IM.Functions.bool_to_bit
            (LeanRV32IM.Functions.zopz0zI_u source.word
              (LeanRV32IM.Functions.sign_extend (m := 32) immediate)))) =
      (Air.Bridge.LtImm.resultBytes
        (Air.Bridge.LtImm.comparison kind source immediate)).word := by
  rw [← immediateBytes_word immediate]
  exact generatedRegValue_eq_resultWord kind source
    (Air.Bridge.LtImm.immediateBytes immediate)

end LeanRV32IM.Publication.ExecutionCompare
