import Pilot
import RiscvRefinement.Sail.Reviewed.Multiply
import RiscvRefinement.Sail.Reviewed.Div

set_option maxHeartbeats 1_000_000_000
set_option maxRecDepth 100_000

open Sail

namespace LeanRV32IM.Functions

private theorem to_bits_truncate_32_eq_ofInt (value : Int) :
    to_bits_truncate (l := 32) value = BitVec.ofInt 32 value := by
  apply BitVec.eq_of_toNat_eq
  simp [to_bits_truncate, Sail.get_slice_int]
  calc
    (value % 8589934592).toNat % 4294967296 =
        ((value % 8589934592) % (4294967296 : Int)).toNat :=
      (Int.toNat_emod
        (x := value % 8589934592) (y := 4294967296)
        (Int.emod_nonneg value (by decide)) (by decide)).symm
    _ = (value % 4294967296).toNat := by
      rw [Int.emod_emod_of_dvd value
        (show (4294967296 : Int) ∣ 8589934592 from ⟨2, by decide⟩)]

private theorem to_bits_truncate_64_eq_ofInt (value : Int) :
    to_bits_truncate (l := 64) value = BitVec.ofInt 64 value := by
  apply BitVec.eq_of_toNat_eq
  simp [to_bits_truncate, Sail.get_slice_int]
  calc
    (value % 36893488147419103232).toNat % 18446744073709551616 =
        ((value % 36893488147419103232) %
          (18446744073709551616 : Int)).toNat :=
      (Int.toNat_emod
        (x := value % 36893488147419103232)
        (y := 18446744073709551616)
        (Int.emod_nonneg value (by decide)) (by decide)).symm
    _ = (value % 18446744073709551616).toNat := by
      rw [Int.emod_emod_of_dvd value
        (show (18446744073709551616 : Int) ∣
          36893488147419103232 from ⟨2, by decide⟩)]

private theorem signExtend64_eq_ofInt (value : BitVec 32) :
    value.signExtend 64 = BitVec.ofInt 64 value.toInt := by
  apply BitVec.eq_of_toInt_eq
  rw [BitVec.toInt_signExtend_of_le (by decide)]
  symm
  apply BitVec.toInt_ofInt_eq_self (by decide)
  · have lower := BitVec.le_toInt value
    omega
  · have upper := BitVec.toInt_lt (x := value)
    omega

private theorem setWidth64_eq_ofIntNat (value : BitVec 32) :
    value.setWidth 64 = BitVec.ofInt 64 (value.toNat : Int) := by
  apply BitVec.eq_of_toNat_eq
  simp [BitVec.toNat_setWidth, Nat.mod_eq_of_lt, value.isLt]

private theorem signedSignedWide
    (source1 source2 : BitVec 32) :
    to_bits_truncate (l := 64) (source1.toInt * source2.toInt) =
      source1.signExtend 64 * source2.signExtend 64 := by
  rw [to_bits_truncate_64_eq_ofInt, BitVec.ofInt_mul]
  rw [signExtend64_eq_ofInt, signExtend64_eq_ofInt]

private theorem signedUnsignedWide
    (source1 source2 : BitVec 32) :
    to_bits_truncate (l := 64)
        (source1.toInt * BitVec.toNatInt source2) =
      source1.signExtend 64 * source2.setWidth 64 := by
  rw [to_bits_truncate_64_eq_ofInt, BitVec.ofInt_mul]
  rw [signExtend64_eq_ofInt, setWidth64_eq_ofIntNat]
  rfl

private theorem unsignedUnsignedWide
    (source1 source2 : BitVec 32) :
    to_bits_truncate (l := 64)
        (BitVec.toNatInt source1 * BitVec.toNatInt source2) =
      source1.setWidth 64 * source2.setWidth 64 := by
  rw [to_bits_truncate_64_eq_ofInt, BitVec.ofInt_mul]
  rw [setWidth64_eq_ofIntNat, setWidth64_eq_ofIntNat]
  rfl

theorem generatedMulValue_eq_reviewed
    (source1 source2 : BitVec 32) :
    mult_to_bits_half .Signed .Signed source1 source2 .Low =
      RiscvRefinement.Sail.Reviewed.executeMulValue source1 source2 := by
  change Sail.BitVec.extractLsb
      (to_bits_truncate (l := 64) (source1.toInt * source2.toInt))
      31 0 = _
  rw [signedSignedWide]
  simpa [
    RiscvRefinement.Sail.Reviewed.executeMulValue,
    Sail.BitVec.extractLsb,
    BitVec.extractLsb,
  ] using (BitVec.setWidth_eq_extractLsb'
    (x := source1.signExtend 64 * source2.signExtend 64)
    (w := 32) (by decide)).symm

theorem generatedMulhValue_eq_reviewed
    (source1 source2 : BitVec 32) :
    mult_to_bits_half .Signed .Signed source1 source2 .High =
      RiscvRefinement.Sail.Reviewed.executeMulhValue source1 source2 := by
  change Sail.BitVec.extractLsb
      (to_bits_truncate (l := 64) (source1.toInt * source2.toInt))
      63 32 = _
  rw [signedSignedWide]
  simpa [
    RiscvRefinement.Sail.Reviewed.executeMulhValue,
    Sail.BitVec.extractLsb,
    BitVec.extractLsb,
  ] using (BitVec.setWidth_ushiftRight_eq_extractLsb
    (b := source1.signExtend 64 * source2.signExtend 64)
    (w' := 32) (w'' := 32)).symm

theorem generatedMulhsuValue_eq_reviewed
    (source1 source2 : BitVec 32) :
    mult_to_bits_half .Signed .Unsigned source1 source2 .High =
      RiscvRefinement.Sail.Reviewed.executeMulhsuValue source1 source2 := by
  change Sail.BitVec.extractLsb
      (to_bits_truncate (l := 64)
        (source1.toInt * BitVec.toNatInt source2)) 63 32 = _
  rw [signedUnsignedWide]
  simpa [
    RiscvRefinement.Sail.Reviewed.executeMulhsuValue,
    Sail.BitVec.extractLsb,
    BitVec.extractLsb,
  ] using (BitVec.setWidth_ushiftRight_eq_extractLsb
    (b := source1.signExtend 64 * source2.setWidth 64)
    (w' := 32) (w'' := 32)).symm

theorem generatedMulhuValue_eq_reviewed
    (source1 source2 : BitVec 32) :
    mult_to_bits_half .Unsigned .Unsigned source1 source2 .High =
      RiscvRefinement.Sail.Reviewed.executeMulhuValue source1 source2 := by
  change Sail.BitVec.extractLsb
      (to_bits_truncate (l := 64)
        (BitVec.toNatInt source1 * BitVec.toNatInt source2)) 63 32 = _
  rw [unsignedUnsignedWide]
  simpa [
    RiscvRefinement.Sail.Reviewed.executeMulhuValue,
    Sail.BitVec.extractLsb,
    BitVec.extractLsb,
  ] using (BitVec.setWidth_ushiftRight_eq_extractLsb
    (b := source1.setWidth 64 * source2.setWidth 64)
    (w' := 32) (w'' := 32)).symm

def generatedDivResult
    (source1 source2 : BitVec 32)
    (isUnsigned : Bool) : BitVec 32 :=
  let dividend :=
    if isUnsigned then BitVec.toNatInt source1 else source1.toInt
  let divisor :=
    if isUnsigned then BitVec.toNatInt source2 else source2.toInt
  let quotient := if divisor == 0 then -1 else Int.tdiv dividend divisor
  let quotient :=
    if (!isUnsigned) && (quotient ≥b (2 ^i (xlen -i 1)))
    then -(2 ^i (xlen -i 1))
    else quotient
  to_bits_truncate (l := 32) quotient

def generatedRemResult
    (source1 source2 : BitVec 32)
    (isUnsigned : Bool) : BitVec 32 :=
  let dividend :=
    if isUnsigned then BitVec.toNatInt source1 else source1.toInt
  let divisor :=
    if isUnsigned then BitVec.toNatInt source2 else source2.toInt
  let remainder :=
    if divisor == 0 then dividend else Int.tmod dividend divisor
  to_bits_truncate (l := 32) remainder

private theorem signedValue_eq_toInt (value : BitVec 32) :
    RiscvRefinement.Arith.signedValue value = value.toInt := by
  unfold RiscvRefinement.Arith.signedValue
  rw [BitVec.toInt_eq_toNat_cond]
  by_cases high : value.toNat < 2147483648
  · have doubled : 2 * value.toNat < 4294967296 := by omega
    simp [high, doubled]
  · have doubled : ¬2 * value.toNat < 4294967296 := by omega
    simp [high, doubled]

private theorem toInt_eq_zero_iff (value : BitVec 32) :
    value.toInt = 0 ↔ value = 0#32 := by
  simpa using (BitVec.toInt_inj (x := value) (y := 0#32))

private theorem toNatInt_eq_zero_iff (value : BitVec 32) :
    BitVec.toNatInt value = 0 ↔ value = 0#32 := by
  change (value.toNat : Int) = 0 ↔ value = 0#32
  rw [Int.ofNat_eq_zero]
  simpa using (BitVec.toNat_inj (x := value) (y := 0#32))

private theorem truncateOverflowQuotient
    (quotient : Int)
    (upper : quotient ≤ 2147483648) :
    to_bits_truncate (l := 32)
        (if quotient ≥b 2147483648 then -2147483648 else quotient) =
      BitVec.ofInt 32 quotient := by
  by_cases overflow : 2147483648 ≤ quotient
  · have exact : quotient = 2147483648 := by omega
    subst quotient
    simp [to_bits_truncate_32_eq_ofInt]
  · have notOverflow : (quotient ≥b 2147483648) = false := by
      simp [overflow]
    simp [notOverflow, to_bits_truncate_32_eq_ofInt]

private theorem signedQuotientUpper
    (source1 source2 : BitVec 32) :
    source1.toInt.tdiv source2.toInt ≤ 2147483648 := by
  have quotientAbs :=
    Int.natAbs_tdiv_le_natAbs source1.toInt source2.toInt
  have quotientAbsInt :
      ((source1.toInt.tdiv source2.toInt).natAbs : Int) ≤
        (source1.toInt.natAbs : Int) := by
    omega
  have sourceAbs : (source1.toInt.natAbs : Int) ≤ 2147483648 := by
    by_cases nonnegative : 0 ≤ source1.toInt
    · rw [Int.natAbs_of_nonneg nonnegative]
      have upper := BitVec.toInt_lt (x := source1)
      omega
    · rw [Int.ofNat_natAbs_of_nonpos (by omega)]
      have lower := BitVec.le_toInt source1
      omega
  have quotientLeAbs :
      source1.toInt.tdiv source2.toInt ≤
        (source1.toInt.tdiv source2.toInt).natAbs :=
    Int.le_natAbs
  omega

theorem generatedDivValue_eq_reviewed
    (source1 source2 : BitVec 32) :
    generatedDivResult source1 source2 false =
      RiscvRefinement.Sail.Reviewed.executeDivValue source1 source2 := by
  by_cases zero : source2 = 0#32
  · subst source2
    apply BitVec.eq_of_toNat_eq
    simp [
      generatedDivResult,
      xlen,
      to_bits_truncate_32_eq_ofInt,
      RiscvRefinement.Sail.Reviewed.executeDivValue,
      RiscvRefinement.Arith.divideSigned,
      RiscvRefinement.Arith.allOnesWord,
      signedValue_eq_toInt,
      RiscvRefinement.zeroWord,
    ]
    decide
  · have divisorNonzero : source2.toInt ≠ 0 := by
      intro divisorZero
      exact zero ((toInt_eq_zero_iff source2).mp divisorZero)
    have zeroWordNe : source2 ≠ RiscvRefinement.zeroWord := by
      simpa [RiscvRefinement.zeroWord] using zero
    rw [RiscvRefinement.Sail.Reviewed.executeDivValue]
    rw [RiscvRefinement.Arith.divideSigned, if_neg zeroWordNe]
    rw [RiscvRefinement.Arith.wrapSigned, signedValue_eq_toInt,
      signedValue_eq_toInt]
    simpa [generatedDivResult, xlen, divisorNonzero] using
      truncateOverflowQuotient
        (source1.toInt.tdiv source2.toInt)
        (signedQuotientUpper source1 source2)

theorem generatedDivuValue_eq_reviewed
    (source1 source2 : BitVec 32) :
    generatedDivResult source1 source2 true =
      RiscvRefinement.Sail.Reviewed.executeDivuValue source1 source2 := by
  by_cases zero : source2 = 0#32
  · subst source2
    apply BitVec.eq_of_toNat_eq
    simp [
      generatedDivResult,
      to_bits_truncate_32_eq_ofInt,
      RiscvRefinement.Sail.Reviewed.executeDivuValue,
      RiscvRefinement.Arith.divideUnsigned,
      RiscvRefinement.Arith.allOnesWord,
      BitVec.toNatInt,
      RiscvRefinement.zeroWord,
    ]
  · have divisorNonzero : BitVec.toNatInt source2 ≠ 0 := by
      intro divisorZero
      exact zero ((toNatInt_eq_zero_iff source2).mp divisorZero)
    have divisorNatNonzero : source2.toNat ≠ 0 := by
      intro divisorZero
      apply zero
      apply BitVec.eq_of_toNat_eq
      simp [divisorZero]
    have zeroWordNe : source2 ≠ RiscvRefinement.zeroWord := by
      simpa [RiscvRefinement.zeroWord] using zero
    simp [
      generatedDivResult,
      divisorNonzero,
      to_bits_truncate_32_eq_ofInt,
      RiscvRefinement.Sail.Reviewed.executeDivuValue,
      RiscvRefinement.Arith.divideUnsigned,
      zeroWordNe,
      BitVec.toNatInt,
      RiscvRefinement.Arith.unsignedValue,
      divisorNatNonzero,
      ← Int.ofNat_tdiv,
    ]
    rw [← BitVec.ofInt_natCast]
    congr 1

theorem generatedRemValue_eq_reviewed
    (source1 source2 : BitVec 32) :
    generatedRemResult source1 source2 false =
      RiscvRefinement.Sail.Reviewed.executeRemValue source1 source2 := by
  by_cases zero : source2 = 0#32
  · subst source2
    simp [
      generatedRemResult,
      to_bits_truncate_32_eq_ofInt,
      RiscvRefinement.Sail.Reviewed.executeRemValue,
      RiscvRefinement.Arith.remainderSigned,
      RiscvRefinement.Arith.wrapSigned,
      signedValue_eq_toInt,
      RiscvRefinement.zeroWord,
    ]
  · have divisorNonzero : source2.toInt ≠ 0 := by
      intro divisorZero
      exact zero ((toInt_eq_zero_iff source2).mp divisorZero)
    have zeroWordNe : source2 ≠ RiscvRefinement.zeroWord := by
      simpa [RiscvRefinement.zeroWord] using zero
    simp [
      generatedRemResult,
      divisorNonzero,
      to_bits_truncate_32_eq_ofInt,
      RiscvRefinement.Sail.Reviewed.executeRemValue,
      RiscvRefinement.Arith.remainderSigned,
      RiscvRefinement.Arith.wrapSigned,
      signedValue_eq_toInt,
      zeroWordNe,
    ]

theorem generatedRemuValue_eq_reviewed
    (source1 source2 : BitVec 32) :
    generatedRemResult source1 source2 true =
      RiscvRefinement.Sail.Reviewed.executeRemuValue source1 source2 := by
  by_cases zero : source2 = 0#32
  · subst source2
    simp [
      generatedRemResult,
      to_bits_truncate_32_eq_ofInt,
      RiscvRefinement.Sail.Reviewed.executeRemuValue,
      RiscvRefinement.Arith.remainderUnsigned,
      BitVec.toNatInt,
      RiscvRefinement.Arith.unsignedValue,
      RiscvRefinement.zeroWord,
    ]
  · have divisorNonzero : BitVec.toNatInt source2 ≠ 0 := by
      intro divisorZero
      exact zero ((toNatInt_eq_zero_iff source2).mp divisorZero)
    have divisorNatNonzero : source2.toNat ≠ 0 := by
      intro divisorZero
      apply zero
      apply BitVec.eq_of_toNat_eq
      simp [divisorZero]
    have zeroWordNe : source2 ≠ RiscvRefinement.zeroWord := by
      simpa [RiscvRefinement.zeroWord] using zero
    simp [
      generatedRemResult,
      divisorNonzero,
      to_bits_truncate_32_eq_ofInt,
      RiscvRefinement.Sail.Reviewed.executeRemuValue,
      RiscvRefinement.Arith.remainderUnsigned,
      zeroWordNe,
      BitVec.toNatInt,
      RiscvRefinement.Arith.unsignedValue,
      divisorNatNonzero,
      ← Int.ofNat_tmod,
    ]
    rw [← BitVec.ofInt_natCast]
    congr 1

end LeanRV32IM.Functions
