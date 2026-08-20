import RiscvRefinement.Publication.TeamB.MulhDiv.Division.Negation
import RiscvRefinement.Publication.TeamB.MulhDiv.Division.ProductArithmetic

namespace RiscvRefinement.Publication.TeamB.MulhDiv

open RiscvRefinement
open RiscvRefinement.Air
open RiscvRefinement.Air.Family
open RiscvRefinement.Air.Generated

namespace Division

abbrev FixedConsequences (_selector : Selector) (row : Row) :=
  FixedBounds row
private theorem signBitOfBound
    (top : Byte)
    (sign : Bool)
    (bound :
      (bitVecM31 top -
        boolM31 sign * M31.reduce 128).val < 2 ^ 7) :
    sign = decide (128 ≤ top.toNat) := by
  have topImage :
      (bitVecM31 top).val = top.toNat :=
    M31.reduce_val_of_lt top.toNat (byteBound top)
  have constantImage : (M31.reduce 128).val = 128 := by decide
  cases sign with
  | false =>
      simp only [boolM31, M31.zero_mul, M31.sub_zero] at bound
      rw [topImage] at bound
      simp [show ¬ 128 ≤ top.toNat by omega]
  | true =>
      simp only [boolM31, M31.one_mul] at bound
      by_cases high : 128 ≤ top.toNat
      · simp [high]
      · have low : top.toNat < 128 := by omega
        have wrapped :=
          M31.sub_val_of_lt
            (bitVecM31 top) (M31.reduce 128)
            (by rw [topImage, constantImage]; exact low)
        rw [topImage, constantImage, M31.modulus_eq] at wrapped
        rw [wrapped] at bound
        omega

private theorem signBitOfDoubledBound
    (top : Byte)
    (sign : Bool)
    (bound :
      ((bitVecM31 top -
          boolM31 sign * M31.reduce 128) *
        M31.reduce 2).val < 2 ^ 8) :
    sign = decide (128 ≤ top.toNat) := by
  have topImage :
      (bitVecM31 top).val = top.toNat :=
    M31.reduce_val_of_lt top.toNat (byteBound top)
  have constantImage : (M31.reduce 128).val = 128 := by decide
  have twoImage : (M31.reduce 2).val = 2 := by decide
  cases sign with
  | false =>
      simp only [boolM31, M31.zero_mul, M31.sub_zero] at bound
      have productBound :
          (bitVecM31 top).val * (M31.reduce 2).val <
            M31.modulus := by
        rw [topImage, twoImage, M31.modulus_eq]
        have topBound := top.isLt
        simp only [Nat.reducePow] at topBound
        omega
      rw [
        M31.mul_val_of_lt _ _ productBound,
        topImage,
        twoImage,
      ] at bound
      simp [show ¬ 128 ≤ top.toNat by omega]
  | true =>
      simp only [boolM31, M31.one_mul] at bound
      by_cases high : 128 ≤ top.toNat
      · simp [high]
      · have low : top.toNat < 128 := by omega
        have difference :=
          M31.sub_val_of_lt
            (bitVecM31 top) (M31.reduce 128)
            (by rw [topImage, constantImage]; exact low)
        rw [topImage, constantImage] at difference
        change
          (((bitVecM31 top - M31.reduce 128).val *
              (M31.reduce 2).val) % M31.modulus) < 2 ^ 8
            at bound
        rw [difference, twoImage] at bound
        have productShape :
            (M31.modulus + top.toNat - 128) * 2 =
              M31.modulus +
                (M31.modulus + 2 * top.toNat - 256) := by
          rw [M31.modulus_eq]
          omega
        rw [productShape, Nat.add_mod_left] at bound
        have remainderBound :
            M31.modulus + 2 * top.toNat - 256 < M31.modulus := by
          rw [M31.modulus_eq]
          omega
        rw [Nat.mod_eq_of_lt remainderBound] at bound
        rw [M31.modulus_eq] at bound
        omega

private theorem canonicalPositiveDiffBounds
    (value : Nat)
    (bound :
      (M31.reduce value - M31.reduce 1).val < 2 ^ 20) :
    1 ≤ (M31.reduce value).val ∧
      (M31.reduce value).val ≤ 2 ^ 20 := by
  have oneImage : (M31.reduce 1).val = 1 := by decide
  by_cases zero : (M31.reduce value).val = 0
  · have wrapped :=
      M31.sub_val_of_lt
        (M31.reduce value) (M31.reduce 1)
        (by rw [zero, oneImage]; omega)
    rw [zero, oneImage, M31.modulus_eq] at wrapped
    rw [wrapped] at bound
    omega
  · have positive : 1 ≤ (M31.reduce value).val := by omega
    have difference :=
      M31.sub_val_of_le
        (M31.reduce value) (M31.reduce 1)
        (by rw [oneImage]; exact positive)
    rw [oneImage] at difference
    rw [difference] at bound
    omega

structure FixedSemanticConsequences
    (row : Row) : Prop where
  productCarry0 : (carry0Field row).val < 2 ^ 11
  productCarry1 : (carry1Field row).val < 2 ^ 11
  productCarry2 : (carry2Field row).val < 2 ^ 11
  productCarry3 : (carry3Field row).val < 2 ^ 11
  productCarry4 : (carry4Field row).val < 2 ^ 11
  productCarry5 : (carry5Field row).val < 2 ^ 11
  productCarry6 : (carry6Field row).val < 2 ^ 11
  productCarry7 : (carry7Field row).val < 2 ^ 11
  dividendSignBit :
    row.isSigned = true →
      row.bSign = decide (128 ≤ row.rs1Next.limb3.toNat)
  divisorSignBit :
    row.isSigned = true →
      row.cSign = decide (128 ≤ row.rs2Next.limb3.toNat)
  quotientSignBit :
    row.isSigned = true →
      row.zeroDivisor = false →
      ¬(row.bSign = true ∧ row.cSign = true) →
      row.qSign = decide (128 ≤ row.quotient.limb3.toNat)
  ltDiffLower :
    row.zeroDivisor = false → row.rZero = false →
      1 ≤ (M31.reduce row.ltDiff).val
  ltDiffUpper :
    row.zeroDivisor = false → row.rZero = false →
      (M31.reduce row.ltDiff).val ≤ 1048576
  sourceOneClock :
    validPreviousClock row.rs1PreviousClock (accessClock row.clock 1)
  sourceTwoClock :
    validPreviousClock row.rs2PreviousClock (accessClock row.clock 2)
  destinationClock :
    validPreviousClock row.rdPreviousClock (accessClock row.clock 3)

private theorem fixedSemanticConsequences
    (selector : Selector)
    (row : Row)
    (admission : Admission row)
    (selectors : SelectorConsequences selector row)
    (fixed : FixedConsequences selector row) :
    FixedSemanticConsequences row := by
  have selected := selectors.selected
  have signedImage :
      signedField row = boolM31 row.isSigned := by
    cases selector <;>
      simp_all [
        signedField,
        DivRow.isSigned,
        boolM31,
      ]
  exact {
    productCarry0 := fixed.carry0Bound
    productCarry1 := fixed.carry1Bound
    productCarry2 := fixed.carry2Bound
    productCarry3 := fixed.carry3Bound
    productCarry4 := fixed.carry4Bound
    productCarry5 := fixed.carry5Bound
    productCarry6 := fixed.carry6Bound
    productCarry7 := fixed.carry7Bound
    dividendSignBit := by
      intro signed
      apply signBitOfDoubledBound
      exact (fixed.operandSignBounds (by
        rw [signedImage, signed]
        rfl)).1
    divisorSignBit := by
      intro signed
      apply signBitOfDoubledBound
      exact (fixed.operandSignBounds (by
        rw [signedImage, signed]
        rfl)).2
    quotientSignBit := by
      intro signed zeroDivisor notBoth
      apply signBitOfBound
      apply fixed.quotientSignBound
      rw [
        quotientSignActiveField,
        signedImage,
        signed,
        zeroDivisor,
      ]
      cases dividendSign : row.bSign <;>
        cases divisorSign : row.cSign <;>
        simp_all [boolM31, selectors.activeOne]
    ltDiffLower := by
      intro zeroDivisor remainderZero
      exact
        (canonicalPositiveDiffBounds row.ltDiff
          (fixed.positiveDiffBound (by
            rw [
              selectors.activeOne,
              specialField,
              zeroDivisor,
              remainderZero,
            ]
            rfl))).1
    ltDiffUpper := by
      intro zeroDivisor remainderZero
      exact
        (canonicalPositiveDiffBounds row.ltDiff
          (fixed.positiveDiffBound (by
            rw [
              selectors.activeOne,
              specialField,
              zeroDivisor,
              remainderZero,
            ]
            rfl))).2
    sourceOneClock :=
      MulhDiv.validPreviousClockOfGap
        row.clock 1 row.rs1PreviousClock
        admission.clockPositive admission.clockBound
        (by omega) (by omega)
        admission.sourceOnePreviousBound
        (by simpa [
          clockGapField,
          accessClockField,
          Air.Bridge.TeamACommon.clockGapField,
          Air.Bridge.TeamACommon.accessClockField,
        ] using fixed.sourceOneGap)
    sourceTwoClock :=
      MulhDiv.validPreviousClockOfGap
        row.clock 2 row.rs2PreviousClock
        admission.clockPositive admission.clockBound
        (by omega) (by omega)
        admission.sourceTwoPreviousBound
        (by simpa [
          clockGapField,
          accessClockField,
          Air.Bridge.TeamACommon.clockGapField,
          Air.Bridge.TeamACommon.accessClockField,
        ] using fixed.sourceTwoGap)
    destinationClock :=
      MulhDiv.validPreviousClockOfGap
        row.clock 3 row.rdPreviousClock
        admission.clockPositive admission.clockBound
        (by omega) (by omega)
        admission.destinationPreviousBound
        (by simpa [
          clockGapField,
          accessClockField,
          Air.Bridge.TeamACommon.clockGapField,
          Air.Bridge.TeamACommon.accessClockField,
        ] using fixed.destinationGap)
  }

private theorem divHighBound (value : Bool) :
    255 * value.toNat ≤ 255 := by
  cases value <;> simp

private theorem remainderHighBound (row : Row) :
    divRemainderHigh row ≤ 255 := by
  simpa [divRemainderHigh] using
    divHighBound (row.bSign && !row.rZero)

private theorem productLe65025
    (left right : Nat)
    (leftBound : left ≤ 255)
    (rightBound : right ≤ 255) :
    left * right ≤ 65025 := by
  simpa using Nat.mul_le_mul leftBound rightBound

private theorem byteLe255 (value : Byte) :
    value.toNat ≤ 255 := by
  have bound := byteLt256 value
  omega

private theorem eightProductsAndRemainderLt600000
    (product0 product1 product2 product3 product4 product5 product6
      product7 remainder : Nat)
    (product0Bound : product0 ≤ 65025)
    (product1Bound : product1 ≤ 65025)
    (product2Bound : product2 ≤ 65025)
    (product3Bound : product3 ≤ 65025)
    (product4Bound : product4 ≤ 65025)
    (product5Bound : product5 ≤ 65025)
    (product6Bound : product6 ≤ 65025)
    (product7Bound : product7 ≤ 65025)
    (remainderBound : remainder ≤ 255) :
    product0 + product1 + product2 + product3 + product4 + product5 +
        product6 + product7 + remainder <
      600000 := by
  omega

private theorem boolHighFieldEqReduce (value : Bool) :
    boolM31 value * M31.reduce 255 =
      M31.reduce (255 * value.toNat) := by
  cases value <;> decide

private theorem remainderHighFieldEqReduce
    (sign zero : Bool) :
    boolM31 sign * (1 - boolM31 zero) * M31.reduce 255 =
      M31.reduce (255 * (sign && !zero).toNat) := by
  cases sign <;> cases zero <;> decide

private theorem quotientHighField_eq_reduce (row : Row) :
    quotientHighField row = M31.reduce (divQuotientHigh row) := by
  exact boolHighFieldEqReduce row.qSign

private theorem divisorHighField_eq_reduce (row : Row) :
    divisorHighField row = M31.reduce (divDivisorHigh row) := by
  exact boolHighFieldEqReduce row.cSign

private theorem dividendHighField_eq_reduce (row : Row) :
    dividendHighField row = M31.reduce (divDividendHigh row) := by
  exact boolHighFieldEqReduce row.bSign

private theorem remainderHighField_eq_reduce (row : Row) :
    remainderHighField row = M31.reduce (divRemainderHigh row) := by
  exact remainderHighFieldEqReduce row.bSign row.rZero

private theorem divConvBounds (row : Row) :
    divConv0 row < 600000 ∧
      divConv1 row < 600000 ∧
      divConv2 row < 600000 ∧
      divConv3 row < 600000 ∧
      divConv4 row < 600000 ∧
      divConv5 row < 600000 ∧
      divConv6 row < 600000 ∧
      divConv7 row < 600000 := by
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · simpa [divConv0] using
      eightProductsAndRemainderLt600000
        (row.rs2Next.limb0.toNat * row.quotient.limb0.toNat)
        0 0 0 0 0 0 0 row.remainder.limb0.toNat
        (productLe65025 _ _
          (byteLe255 row.rs2Next.limb0)
          (byteLe255 row.quotient.limb0))
        (by decide) (by decide) (by decide) (by decide)
        (by decide) (by decide) (by decide)
        (byteLe255 row.remainder.limb0)
  · simpa [divConv1] using
      eightProductsAndRemainderLt600000
        (row.rs2Next.limb0.toNat * row.quotient.limb1.toNat)
        (row.rs2Next.limb1.toNat * row.quotient.limb0.toNat)
        0 0 0 0 0 0 row.remainder.limb1.toNat
        (productLe65025 _ _
          (byteLe255 row.rs2Next.limb0)
          (byteLe255 row.quotient.limb1))
        (productLe65025 _ _
          (byteLe255 row.rs2Next.limb1)
          (byteLe255 row.quotient.limb0))
        (by decide) (by decide) (by decide) (by decide)
        (by decide) (by decide)
        (byteLe255 row.remainder.limb1)
  · simpa [divConv2] using
      eightProductsAndRemainderLt600000
        (row.rs2Next.limb0.toNat * row.quotient.limb2.toNat)
        (row.rs2Next.limb1.toNat * row.quotient.limb1.toNat)
        (row.rs2Next.limb2.toNat * row.quotient.limb0.toNat)
        0 0 0 0 0 row.remainder.limb2.toNat
        (productLe65025 _ _
          (byteLe255 row.rs2Next.limb0)
          (byteLe255 row.quotient.limb2))
        (productLe65025 _ _
          (byteLe255 row.rs2Next.limb1)
          (byteLe255 row.quotient.limb1))
        (productLe65025 _ _
          (byteLe255 row.rs2Next.limb2)
          (byteLe255 row.quotient.limb0))
        (by decide) (by decide) (by decide) (by decide) (by decide)
        (byteLe255 row.remainder.limb2)
  · simpa [divConv3] using
      eightProductsAndRemainderLt600000
        (row.rs2Next.limb0.toNat * row.quotient.limb3.toNat)
        (row.rs2Next.limb1.toNat * row.quotient.limb2.toNat)
        (row.rs2Next.limb2.toNat * row.quotient.limb1.toNat)
        (row.rs2Next.limb3.toNat * row.quotient.limb0.toNat)
        0 0 0 0 row.remainder.limb3.toNat
        (productLe65025 _ _
          (byteLe255 row.rs2Next.limb0)
          (byteLe255 row.quotient.limb3))
        (productLe65025 _ _
          (byteLe255 row.rs2Next.limb1)
          (byteLe255 row.quotient.limb2))
        (productLe65025 _ _
          (byteLe255 row.rs2Next.limb2)
          (byteLe255 row.quotient.limb1))
        (productLe65025 _ _
          (byteLe255 row.rs2Next.limb3)
          (byteLe255 row.quotient.limb0))
        (by decide) (by decide) (by decide) (by decide)
        (byteLe255 row.remainder.limb3)
  · simpa [divConv4] using
      eightProductsAndRemainderLt600000
        (row.rs2Next.limb0.toNat * divQuotientHigh row)
        (row.rs2Next.limb1.toNat * row.quotient.limb3.toNat)
        (row.rs2Next.limb2.toNat * row.quotient.limb2.toNat)
        (row.rs2Next.limb3.toNat * row.quotient.limb1.toNat)
        (divDivisorHigh row * row.quotient.limb0.toNat)
        0 0 0 (divRemainderHigh row)
        (productLe65025 _ _
          (byteLe255 row.rs2Next.limb0) (divHighBound row.qSign))
        (productLe65025 _ _
          (byteLe255 row.rs2Next.limb1)
          (byteLe255 row.quotient.limb3))
        (productLe65025 _ _
          (byteLe255 row.rs2Next.limb2)
          (byteLe255 row.quotient.limb2))
        (productLe65025 _ _
          (byteLe255 row.rs2Next.limb3)
          (byteLe255 row.quotient.limb1))
        (productLe65025 _ _
          (divHighBound row.cSign) (byteLe255 row.quotient.limb0))
        (by decide) (by decide) (by decide)
        (remainderHighBound row)
  · simpa [divConv5] using
      eightProductsAndRemainderLt600000
        (row.rs2Next.limb0.toNat * divQuotientHigh row)
        (row.rs2Next.limb1.toNat * divQuotientHigh row)
        (row.rs2Next.limb2.toNat * row.quotient.limb3.toNat)
        (row.rs2Next.limb3.toNat * row.quotient.limb2.toNat)
        (divDivisorHigh row * row.quotient.limb0.toNat)
        (divDivisorHigh row * row.quotient.limb1.toNat)
        0 0 (divRemainderHigh row)
        (productLe65025 _ _
          (byteLe255 row.rs2Next.limb0) (divHighBound row.qSign))
        (productLe65025 _ _
          (byteLe255 row.rs2Next.limb1) (divHighBound row.qSign))
        (productLe65025 _ _
          (byteLe255 row.rs2Next.limb2)
          (byteLe255 row.quotient.limb3))
        (productLe65025 _ _
          (byteLe255 row.rs2Next.limb3)
          (byteLe255 row.quotient.limb2))
        (productLe65025 _ _
          (divHighBound row.cSign) (byteLe255 row.quotient.limb0))
        (productLe65025 _ _
          (divHighBound row.cSign) (byteLe255 row.quotient.limb1))
        (by decide) (by decide)
        (remainderHighBound row)
  · simpa [divConv6] using
      eightProductsAndRemainderLt600000
        (row.rs2Next.limb0.toNat * divQuotientHigh row)
        (row.rs2Next.limb1.toNat * divQuotientHigh row)
        (row.rs2Next.limb2.toNat * divQuotientHigh row)
        (row.rs2Next.limb3.toNat * row.quotient.limb3.toNat)
        (divDivisorHigh row * row.quotient.limb0.toNat)
        (divDivisorHigh row * row.quotient.limb1.toNat)
        (divDivisorHigh row * row.quotient.limb2.toNat)
        0 (divRemainderHigh row)
        (productLe65025 _ _
          (byteLe255 row.rs2Next.limb0) (divHighBound row.qSign))
        (productLe65025 _ _
          (byteLe255 row.rs2Next.limb1) (divHighBound row.qSign))
        (productLe65025 _ _
          (byteLe255 row.rs2Next.limb2) (divHighBound row.qSign))
        (productLe65025 _ _
          (byteLe255 row.rs2Next.limb3)
          (byteLe255 row.quotient.limb3))
        (productLe65025 _ _
          (divHighBound row.cSign) (byteLe255 row.quotient.limb0))
        (productLe65025 _ _
          (divHighBound row.cSign) (byteLe255 row.quotient.limb1))
        (productLe65025 _ _
          (divHighBound row.cSign) (byteLe255 row.quotient.limb2))
        (by decide)
        (remainderHighBound row)
  · simpa [divConv7] using
      eightProductsAndRemainderLt600000
        (row.rs2Next.limb0.toNat * divQuotientHigh row)
        (row.rs2Next.limb1.toNat * divQuotientHigh row)
        (row.rs2Next.limb2.toNat * divQuotientHigh row)
        (row.rs2Next.limb3.toNat * divQuotientHigh row)
        (divDivisorHigh row * row.quotient.limb0.toNat)
        (divDivisorHigh row * row.quotient.limb1.toNat)
        (divDivisorHigh row * row.quotient.limb2.toNat)
        (divDivisorHigh row * row.quotient.limb3.toNat)
        (divRemainderHigh row)
        (productLe65025 _ _
          (byteLe255 row.rs2Next.limb0) (divHighBound row.qSign))
        (productLe65025 _ _
          (byteLe255 row.rs2Next.limb1) (divHighBound row.qSign))
        (productLe65025 _ _
          (byteLe255 row.rs2Next.limb2) (divHighBound row.qSign))
        (productLe65025 _ _
          (byteLe255 row.rs2Next.limb3) (divHighBound row.qSign))
        (productLe65025 _ _
          (divHighBound row.cSign) (byteLe255 row.quotient.limb0))
        (productLe65025 _ _
          (divHighBound row.cSign) (byteLe255 row.quotient.limb1))
        (productLe65025 _ _
          (divHighBound row.cSign) (byteLe255 row.quotient.limb2))
        (productLe65025 _ _
          (divHighBound row.cSign) (byteLe255 row.quotient.limb3))
        (remainderHighBound row)

private structure PreservedA
    (source normalized : Row) : Prop where
  pc : normalized.pc = source.pc
  clock : normalized.clock = source.clock
  rd : normalized.rd = source.rd

  rdPreviousClock :
    normalized.rdPreviousClock = source.rdPreviousClock

private structure PreservedB
    (source normalized : Row) : Prop where
  rdPrevious : normalized.rdPrevious = source.rdPrevious
  rdNext : normalized.rdNext = source.rdNext
  rs1 : normalized.rs1 = source.rs1
  rs1PreviousClock :
    normalized.rs1PreviousClock = source.rs1PreviousClock

private structure PreservedC
    (source normalized : Row) : Prop where
  rs1Previous : normalized.rs1Previous = source.rs1Previous
  rs1Next : normalized.rs1Next = source.rs1Next
  rs2 : normalized.rs2 = source.rs2
  rs2PreviousClock :
    normalized.rs2PreviousClock = source.rs2PreviousClock

private structure PreservedD
    (source normalized : Row) : Prop where
  rs2Previous : normalized.rs2Previous = source.rs2Previous
  rs2Next : normalized.rs2Next = source.rs2Next
  zeroDivisor : normalized.zeroDivisor = source.zeroDivisor
  rZero : normalized.rZero = source.rZero

private structure PreservedE
    (source normalized : Row) : Prop where
  quotient : normalized.quotient = source.quotient
  remainder : normalized.remainder = source.remainder
  bSign : normalized.bSign = source.bSign
  cSign : normalized.cSign = source.cSign

private structure PreservedF
    (source normalized : Row) : Prop where
  qSign : normalized.qSign = source.qSign
  signXor : normalized.signXor = source.signXor
  remainderAbs : normalized.remainderAbs = source.remainderAbs
  ltMarker0 : normalized.ltMarker0 = source.ltMarker0

private structure PreservedG
    (source normalized : Row) : Prop where
  ltMarker1 : normalized.ltMarker1 = source.ltMarker1
  ltMarker2 : normalized.ltMarker2 = source.ltMarker2
  ltMarker3 : normalized.ltMarker3 = source.ltMarker3
  isDiv : normalized.isDiv = source.isDiv

private structure PreservedH
    (source normalized : Row) : Prop where
  isDivu : normalized.isDivu = source.isDivu
  isRem : normalized.isRem = source.isRem
  isRemu : normalized.isRemu = source.isRemu
  destinationNonzero :
    normalized.destinationNonzero = source.destinationNonzero

private structure NormalizedControl
    (source normalized : Row) : Prop where
  ltDiff :
    normalized.ltDiff = (M31.reduce source.ltDiff).val
  claimedNextPc :
    normalized.claimedNextPc = nextPc source.pc

private structure NormalizationTailSpec
    (source normalized : Row) : Prop where
  preservedG : PreservedG source normalized
  preservedH : PreservedH source normalized
  control : NormalizedControl source normalized

private structure NormalizationSpec
    (source normalized : Row) : Prop where
  preservedA : PreservedA source normalized
  preservedB : PreservedB source normalized
  preservedC : PreservedC source normalized
  preservedD : PreservedD source normalized
  preservedE : PreservedE source normalized
  preservedF : PreservedF source normalized
  tail : NormalizationTailSpec source normalized

private theorem normalizationExists (row : Row) :
    ∃ normalized : Row, NormalizationSpec row normalized := by
  let normalized : Row := {
    pc := row.pc
    clock := row.clock
    rd := row.rd
    rdPreviousClock := row.rdPreviousClock
    rdPrevious := row.rdPrevious
    rdNext := row.rdNext
    rs1 := row.rs1
    rs1PreviousClock := row.rs1PreviousClock
    rs1Previous := row.rs1Previous
    rs1Next := row.rs1Next
    rs2 := row.rs2
    rs2PreviousClock := row.rs2PreviousClock
    rs2Previous := row.rs2Previous
    rs2Next := row.rs2Next
    zeroDivisor := row.zeroDivisor
    rZero := row.rZero
    quotient := row.quotient
    remainder := row.remainder
    bSign := row.bSign
    cSign := row.cSign
    qSign := row.qSign
    signXor := row.signXor
    remainderAbs := row.remainderAbs
    ltMarker0 := row.ltMarker0
    ltMarker1 := row.ltMarker1
    ltMarker2 := row.ltMarker2
    ltMarker3 := row.ltMarker3
    ltDiff := (M31.reduce row.ltDiff).val
    isDiv := row.isDiv
    isDivu := row.isDivu
    isRem := row.isRem
    isRemu := row.isRemu
    destinationNonzero := row.destinationNonzero
    claimedNextPc := nextPc row.pc
  }
  have preservedA : PreservedA row normalized := by
    exact {
      pc := rfl
      clock := rfl
      rd := rfl
      rdPreviousClock := rfl
    }
  have preservedB : PreservedB row normalized := by
    exact {
      rdPrevious := rfl
      rdNext := rfl
      rs1 := rfl
      rs1PreviousClock := rfl
    }
  have preservedC : PreservedC row normalized := by
    exact {
      rs1Previous := rfl
      rs1Next := rfl
      rs2 := rfl
      rs2PreviousClock := rfl
    }
  have preservedD : PreservedD row normalized := by
    exact {
      rs2Previous := rfl
      rs2Next := rfl
      zeroDivisor := rfl
      rZero := rfl
    }
  have preservedE : PreservedE row normalized := by
    exact {
      quotient := rfl
      remainder := rfl
      bSign := rfl
      cSign := rfl
    }
  have preservedF : PreservedF row normalized := by
    exact {
      qSign := rfl
      signXor := rfl
      remainderAbs := rfl
      ltMarker0 := rfl
    }
  have preservedG : PreservedG row normalized := by
    exact {
      ltMarker1 := rfl
      ltMarker2 := rfl
      ltMarker3 := rfl
      isDiv := rfl
    }
  have preservedH : PreservedH row normalized := by
    exact {
      isDivu := rfl
      isRem := rfl
      isRemu := rfl
      destinationNonzero := rfl
    }
  have control : NormalizedControl row normalized := by
    exact {
      ltDiff := rfl
      claimedNextPc := rfl
    }
  have tail : NormalizationTailSpec row normalized := by
    exact {
      preservedG := preservedG
      preservedH := preservedH
      control := control
    }
  exact ⟨normalized, {
    preservedA := preservedA
    preservedB := preservedB
    preservedC := preservedC
    preservedD := preservedD
    preservedE := preservedE
    preservedF := preservedF
    tail := tail
  }⟩

noncomputable def normalize (row : Row) : Row :=
  Classical.choose (normalizationExists row)

private theorem normalize_spec (row : Row) :
    NormalizationSpec row (normalize row) :=
  Classical.choose_spec (normalizationExists row)

@[simp] private theorem normalize_pc (row : Row) :
    (normalize row).pc = row.pc :=
  (normalize_spec row).preservedA.pc

@[simp] private theorem normalize_clock (row : Row) :
    (normalize row).clock = row.clock :=
  (normalize_spec row).preservedA.clock

@[simp] private theorem normalize_rd (row : Row) :
    (normalize row).rd = row.rd :=
  (normalize_spec row).preservedA.rd

@[simp] private theorem normalize_rdPreviousClock (row : Row) :
    (normalize row).rdPreviousClock = row.rdPreviousClock :=
  (normalize_spec row).preservedA.rdPreviousClock

@[simp] private theorem normalize_rdPrevious (row : Row) :
    (normalize row).rdPrevious = row.rdPrevious :=
  (normalize_spec row).preservedB.rdPrevious

@[simp] private theorem normalize_rdNext (row : Row) :
    (normalize row).rdNext = row.rdNext :=
  (normalize_spec row).preservedB.rdNext

@[simp] private theorem normalize_rs1 (row : Row) :
    (normalize row).rs1 = row.rs1 :=
  (normalize_spec row).preservedB.rs1

@[simp] private theorem normalize_rs1PreviousClock (row : Row) :
    (normalize row).rs1PreviousClock = row.rs1PreviousClock :=
  (normalize_spec row).preservedB.rs1PreviousClock

@[simp] private theorem normalize_rs1Previous (row : Row) :
    (normalize row).rs1Previous = row.rs1Previous :=
  (normalize_spec row).preservedC.rs1Previous

@[simp] private theorem normalize_rs1Next (row : Row) :
    (normalize row).rs1Next = row.rs1Next :=
  (normalize_spec row).preservedC.rs1Next

@[simp] private theorem normalize_rs2 (row : Row) :
    (normalize row).rs2 = row.rs2 :=
  (normalize_spec row).preservedC.rs2

@[simp] private theorem normalize_rs2PreviousClock (row : Row) :
    (normalize row).rs2PreviousClock = row.rs2PreviousClock :=
  (normalize_spec row).preservedC.rs2PreviousClock

@[simp] private theorem normalize_rs2Previous (row : Row) :
    (normalize row).rs2Previous = row.rs2Previous :=
  (normalize_spec row).preservedD.rs2Previous

@[simp] private theorem normalize_rs2Next (row : Row) :
    (normalize row).rs2Next = row.rs2Next :=
  (normalize_spec row).preservedD.rs2Next

@[simp] private theorem normalize_zeroDivisor (row : Row) :
    (normalize row).zeroDivisor = row.zeroDivisor :=
  (normalize_spec row).preservedD.zeroDivisor

@[simp] private theorem normalize_rZero (row : Row) :
    (normalize row).rZero = row.rZero :=
  (normalize_spec row).preservedD.rZero

@[simp] private theorem normalize_quotient (row : Row) :
    (normalize row).quotient = row.quotient :=
  (normalize_spec row).preservedE.quotient

@[simp] private theorem normalize_remainder (row : Row) :
    (normalize row).remainder = row.remainder :=
  (normalize_spec row).preservedE.remainder

@[simp] private theorem normalize_bSign (row : Row) :
    (normalize row).bSign = row.bSign :=
  (normalize_spec row).preservedE.bSign

@[simp] private theorem normalize_cSign (row : Row) :
    (normalize row).cSign = row.cSign :=
  (normalize_spec row).preservedE.cSign

@[simp] private theorem normalize_qSign (row : Row) :
    (normalize row).qSign = row.qSign :=
  (normalize_spec row).preservedF.qSign

@[simp] private theorem normalize_signXor (row : Row) :
    (normalize row).signXor = row.signXor :=
  (normalize_spec row).preservedF.signXor

@[simp] private theorem normalize_remainderAbs (row : Row) :
    (normalize row).remainderAbs = row.remainderAbs :=
  (normalize_spec row).preservedF.remainderAbs

@[simp] private theorem normalize_ltMarker0 (row : Row) :
    (normalize row).ltMarker0 = row.ltMarker0 :=
  (normalize_spec row).preservedF.ltMarker0

@[simp] private theorem normalize_ltMarker1 (row : Row) :
    (normalize row).ltMarker1 = row.ltMarker1 :=
  (normalize_spec row).tail.preservedG.ltMarker1

@[simp] private theorem normalize_ltMarker2 (row : Row) :
    (normalize row).ltMarker2 = row.ltMarker2 :=
  (normalize_spec row).tail.preservedG.ltMarker2

@[simp] private theorem normalize_ltMarker3 (row : Row) :
    (normalize row).ltMarker3 = row.ltMarker3 :=
  (normalize_spec row).tail.preservedG.ltMarker3

@[simp] private theorem normalize_isDiv (row : Row) :
    (normalize row).isDiv = row.isDiv :=
  (normalize_spec row).tail.preservedG.isDiv

@[simp] private theorem normalize_isDivu (row : Row) :
    (normalize row).isDivu = row.isDivu :=
  (normalize_spec row).tail.preservedH.isDivu

@[simp] private theorem normalize_isRem (row : Row) :
    (normalize row).isRem = row.isRem :=
  (normalize_spec row).tail.preservedH.isRem

@[simp] private theorem normalize_isRemu (row : Row) :
    (normalize row).isRemu = row.isRemu :=
  (normalize_spec row).tail.preservedH.isRemu

@[simp] private theorem normalize_destinationNonzero (row : Row) :
    (normalize row).destinationNonzero = row.destinationNonzero :=
  (normalize_spec row).tail.preservedH.destinationNonzero

@[simp] private theorem normalize_ltDiff (row : Row) :
    (normalize row).ltDiff = (M31.reduce row.ltDiff).val :=
  (normalize_spec row).tail.control.ltDiff

@[simp] private theorem normalize_claimedNextPc (row : Row) :
    (normalize row).claimedNextPc = nextPc row.pc :=
  (normalize_spec row).tail.control.claimedNextPc

@[simp] private theorem normalize_isSigned (row : Row) :
    (normalize row).isSigned = row.isSigned := by
  simp only [DivRow.isSigned, normalize_isDiv, normalize_isRem]

@[simp] private theorem normalize_isDivision (row : Row) :
    (normalize row).isDivision = row.isDivision := by
  simp only [DivRow.isDivision, normalize_isDiv, normalize_isDivu]

@[simp] private theorem normalize_divDividendHigh (row : Row) :
    divDividendHigh (normalize row) = divDividendHigh row := by
  simp only [divDividendHigh, normalize_bSign]

@[simp] private theorem normalize_divDivisorHigh (row : Row) :
    divDivisorHigh (normalize row) = divDivisorHigh row := by

  simp only [divDivisorHigh, normalize_cSign]

@[simp] private theorem normalize_divQuotientHigh (row : Row) :
    divQuotientHigh (normalize row) = divQuotientHigh row := by
  simp only [divQuotientHigh, normalize_qSign]

@[simp] private theorem normalize_divRemainderHigh (row : Row) :
    divRemainderHigh (normalize row) = divRemainderHigh row := by
  simp only [
    divRemainderHigh,
    normalize_bSign,
    normalize_rZero,
  ]

@[simp] private theorem normalize_divConv0 (row : Row) :
    divConv0 (normalize row) = divConv0 row := by
  simp only [
    divConv0,
    normalize_rs2Next,
    normalize_quotient,
    normalize_remainder,
  ]

@[simp] private theorem normalize_divConv1 (row : Row) :
    divConv1 (normalize row) = divConv1 row := by
  simp only [
    divConv1,
    normalize_rs2Next,
    normalize_quotient,
    normalize_remainder,
  ]

@[simp] private theorem normalize_divConv2 (row : Row) :
    divConv2 (normalize row) = divConv2 row := by
  simp only [
    divConv2,
    normalize_rs2Next,
    normalize_quotient,
    normalize_remainder,
  ]

@[simp] private theorem normalize_divConv3 (row : Row) :
    divConv3 (normalize row) = divConv3 row := by
  simp only [
    divConv3,
    normalize_rs2Next,
    normalize_quotient,
    normalize_remainder,
  ]

@[simp] private theorem normalize_divConv4 (row : Row) :
    divConv4 (normalize row) = divConv4 row := by
  simp only [
    divConv4,
    normalize_rs2Next,
    normalize_quotient,
    normalize_divQuotientHigh,
    normalize_divDivisorHigh,
    normalize_divRemainderHigh,
  ]

@[simp] private theorem normalize_divConv5 (row : Row) :
    divConv5 (normalize row) = divConv5 row := by
  simp only [
    divConv5,
    normalize_rs2Next,
    normalize_quotient,
    normalize_divQuotientHigh,
    normalize_divDivisorHigh,
    normalize_divRemainderHigh,
  ]

@[simp] private theorem normalize_divConv6 (row : Row) :
    divConv6 (normalize row) = divConv6 row := by
  simp only [
    divConv6,
    normalize_rs2Next,
    normalize_quotient,
    normalize_divQuotientHigh,
    normalize_divDivisorHigh,
    normalize_divRemainderHigh,
  ]

@[simp] private theorem normalize_divConv7 (row : Row) :
    divConv7 (normalize row) = divConv7 row := by
  simp only [
    divConv7,
    normalize_rs2Next,
    normalize_quotient,
    normalize_divQuotientHigh,
    normalize_divDivisorHigh,
    normalize_divRemainderHigh,
  ]

@[simp] private theorem normalize_divCompareDiff0 (row : Row) :
    divCompareDiff0 (normalize row) = divCompareDiff0 row := by
  simp only [
    divCompareDiff0,
    divCompareDiff,
    normalize_cSign,
    normalize_rs2Next,
    normalize_remainderAbs,
  ]

@[simp] private theorem normalize_divCompareDiff1 (row : Row) :
    divCompareDiff1 (normalize row) = divCompareDiff1 row := by
  simp only [
    divCompareDiff1,
    divCompareDiff,
    normalize_cSign,
    normalize_rs2Next,
    normalize_remainderAbs,
  ]

@[simp] private theorem normalize_divCompareDiff2 (row : Row) :
    divCompareDiff2 (normalize row) = divCompareDiff2 row := by
  simp only [
    divCompareDiff2,
    divCompareDiff,
    normalize_cSign,
    normalize_rs2Next,
    normalize_remainderAbs,
  ]

@[simp] private theorem normalize_divCompareDiff3 (row : Row) :
    divCompareDiff3 (normalize row) = divCompareDiff3 row := by
  simp only [
    divCompareDiff3,
    divCompareDiff,
    normalize_cSign,
    normalize_rs2Next,
    normalize_remainderAbs,
  ]

@[simp] private theorem normalize_divResultBytes (row : Row) :
    divResultBytes (normalize row) = divResultBytes row := by
  simp only [
    divResultBytes,
    normalize_isDivision,
    normalize_quotient,
    normalize_remainder,
  ]

def normalizeEnvironment
    (row : Row)
    (environment : Opcodes.DivEnvironment row) :
    Opcodes.DivEnvironment (normalize row) where
  pre := environment.pre
  pcBinds := by
    simpa only [normalize_pc] using environment.pcBinds
  dividendBinds := by
    simpa only [normalize_rs1Previous, normalize_rs1] using
      environment.dividendBinds
  divisorBinds := by
    simpa only [normalize_rs2Previous, normalize_rs2] using
      environment.divisorBinds
  destinationBinds := by
    simpa only [normalize_rdPrevious, normalize_rd] using
      environment.destinationBinds

private theorem divConvLtModulus
    {convolution : Nat}
    (bound : convolution < 600000) :
    convolution < M31.modulus := by
  rw [M31.modulus_eq]
  omega

private theorem carryPlusDivConvLtModulus
    (carry convolution : Nat)
    (carryBound : carry < 2 ^ 11)
    (convolutionBound : convolution < 600000) :
    carry + convolution < M31.modulus := by
  rw [M31.modulus_eq]
  omega

private theorem divHighLt256 (value : Bool) :
    255 * value.toNat < 2 ^ 8 := by
  have bound := divHighBound value
  omega

set_option maxRecDepth 30000 in
private theorem productRecurrence0
    (row : Row)
    (fixed : FixedSemanticConsequences row)
    (convBound : divConv0 row < 600000) :
    divConv0 row =
      row.rs1Next.limb0.toNat + 256 * (carry0Field row).val := by
  apply MulhDiv.carryEquationOfField
  · exact divConvLtModulus convBound
  · exact byteLt256 row.rs1Next.limb0
  · exact fixed.productCarry0
  · simpa [
      carry0Field,
      divConv0,
      bitVecM31,
      Air.Bridge.TeamACommon.reduceMul,
      Air.Bridge.TeamACommon.reduceAdd,
    ]

set_option maxRecDepth 30000 in
private theorem productRecurrence1
    (row : Row)
    (fixed : FixedSemanticConsequences row)
    (convBound : divConv1 row < 600000) :
    (carry0Field row).val + divConv1 row =
      row.rs1Next.limb1.toNat + 256 * (carry1Field row).val := by
  apply MulhDiv.carryEquationOfField
  · exact
      carryPlusDivConvLtModulus
        (carry0Field row).val (divConv1 row)
        fixed.productCarry0 convBound
  · exact byteLt256 row.rs1Next.limb1
  · exact fixed.productCarry1
  · exact productRecurrence1FieldEquation row

set_option maxRecDepth 30000 in
private theorem productRecurrence2
    (row : Row)
    (fixed : FixedSemanticConsequences row)
    (convBound : divConv2 row < 600000) :
    (carry1Field row).val + divConv2 row =
      row.rs1Next.limb2.toNat + 256 * (carry2Field row).val := by
  apply MulhDiv.carryEquationOfField
  · exact
      carryPlusDivConvLtModulus
        (carry1Field row).val (divConv2 row)
        fixed.productCarry1 convBound
  · exact byteLt256 row.rs1Next.limb2
  · exact fixed.productCarry2
  · exact productRecurrence2FieldEquation row

set_option maxRecDepth 30000 in
private theorem productRecurrence3
    (row : Row)
    (fixed : FixedSemanticConsequences row)
    (convBound : divConv3 row < 600000) :
    (carry2Field row).val + divConv3 row =
      row.rs1Next.limb3.toNat + 256 * (carry3Field row).val := by
  apply MulhDiv.carryEquationOfField
  · exact
      carryPlusDivConvLtModulus
        (carry2Field row).val (divConv3 row)
        fixed.productCarry2 convBound
  · exact byteLt256 row.rs1Next.limb3
  · exact fixed.productCarry3
  · exact productRecurrence3FieldEquation row

set_option maxRecDepth 30000 in
private theorem productRecurrence4
    (row : Row)
    (fixed : FixedSemanticConsequences row)
    (convBound : divConv4 row < 600000) :
    (carry3Field row).val + divConv4 row =
      divDividendHigh row + 256 * (carry4Field row).val := by
  apply MulhDiv.carryEquationOfField
  · exact
      carryPlusDivConvLtModulus
        (carry3Field row).val (divConv4 row)
        fixed.productCarry3 convBound
  · exact divHighLt256 row.bSign
  · exact fixed.productCarry4
  · exact productRecurrence4FieldEquation row

set_option maxRecDepth 30000 in
private theorem productRecurrence5
    (row : Row)
    (fixed : FixedSemanticConsequences row)
    (convBound : divConv5 row < 600000) :
    (carry4Field row).val + divConv5 row =
      divDividendHigh row + 256 * (carry5Field row).val := by
  apply MulhDiv.carryEquationOfField
  · exact
      carryPlusDivConvLtModulus
        (carry4Field row).val (divConv5 row)
        fixed.productCarry4 convBound
  · exact divHighLt256 row.bSign
  · exact fixed.productCarry5
  · exact productRecurrence5FieldEquation row

set_option maxRecDepth 30000 in
private theorem productRecurrence6
    (row : Row)
    (fixed : FixedSemanticConsequences row)
    (convBound : divConv6 row < 600000) :
    (carry5Field row).val + divConv6 row =
      divDividendHigh row + 256 * (carry6Field row).val := by
  apply MulhDiv.carryEquationOfField
  · exact
      carryPlusDivConvLtModulus

        (carry5Field row).val (divConv6 row)
        fixed.productCarry5 convBound
  · exact divHighLt256 row.bSign
  · exact fixed.productCarry6
  · exact productRecurrence6FieldEquation row

set_option maxRecDepth 30000 in
private theorem productRecurrence7
    (row : Row)
    (fixed : FixedSemanticConsequences row)
    (convBound : divConv7 row < 600000) :
    (carry6Field row).val + divConv7 row =
      divDividendHigh row + 256 * (carry7Field row).val := by
  apply MulhDiv.carryEquationOfField
  · exact
      carryPlusDivConvLtModulus
        (carry6Field row).val (divConv7 row)
        fixed.productCarry6 convBound
  · exact divHighLt256 row.bSign
  · exact fixed.productCarry7
  · exact productRecurrence7FieldEquation row

set_option maxRecDepth 30000 in
private theorem productRecurrenceOfFixed
    (row : Row)
    (fixed : FixedSemanticConsequences row) :
    ∃ k0 k1 k2 k3 k4 k5 k6 k7 : Nat,
      k0 < 2048 ∧ k1 < 2048 ∧ k2 < 2048 ∧ k3 < 2048 ∧
      k4 < 2048 ∧ k5 < 2048 ∧ k6 < 2048 ∧ k7 < 2048 ∧
      divConv0 (normalize row) =
        (normalize row).rs1Next.limb0.toNat + 256 * k0 ∧
      k0 + divConv1 (normalize row) =
        (normalize row).rs1Next.limb1.toNat + 256 * k1 ∧
      k1 + divConv2 (normalize row) =
        (normalize row).rs1Next.limb2.toNat + 256 * k2 ∧
      k2 + divConv3 (normalize row) =
        (normalize row).rs1Next.limb3.toNat + 256 * k3 ∧
      k3 + divConv4 (normalize row) =
        divDividendHigh (normalize row) + 256 * k4 ∧
      k4 + divConv5 (normalize row) =
        divDividendHigh (normalize row) + 256 * k5 ∧
      k5 + divConv6 (normalize row) =
        divDividendHigh (normalize row) + 256 * k6 ∧
      k6 + divConv7 (normalize row) =
        divDividendHigh (normalize row) + 256 * k7 := by
  rcases divConvBounds row with
    ⟨conv0, conv1, conv2, conv3, conv4, conv5, conv6, conv7⟩
  refine ⟨
    (carry0Field row).val,
    (carry1Field row).val,
    (carry2Field row).val,
    (carry3Field row).val,
    (carry4Field row).val,
    (carry5Field row).val,
    (carry6Field row).val,
    (carry7Field row).val,
    fixed.productCarry0,
    fixed.productCarry1,
    fixed.productCarry2,
    fixed.productCarry3,
    fixed.productCarry4,
    fixed.productCarry5,
    fixed.productCarry6,
    fixed.productCarry7,
    ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · simpa only [normalize_divConv0, normalize_rs1Next] using
      productRecurrence0 row fixed conv0
  · simpa only [normalize_divConv1, normalize_rs1Next] using
      productRecurrence1 row fixed conv1
  · simpa only [normalize_divConv2, normalize_rs1Next] using
      productRecurrence2 row fixed conv2
  · simpa only [normalize_divConv3, normalize_rs1Next] using
      productRecurrence3 row fixed conv3
  · simpa only [
      normalize_divConv4,
      normalize_divDividendHigh,
    ] using productRecurrence4 row fixed conv4
  · simpa only [
      normalize_divConv5,
      normalize_divDividendHigh,
    ] using productRecurrence5 row fixed conv5
  · simpa only [
      normalize_divConv6,
      normalize_divDividendHigh,
    ] using productRecurrence6 row fixed conv6
  · simpa only [
      normalize_divConv7,
      normalize_divDividendHigh,
    ] using productRecurrence7 row fixed conv7

private theorem compareDiffZeroOfField
    (row : Row)
    (divisor absolute : Byte)
    (equation : compareDiffField row divisor absolute = 0) :
    divCompareDiff row divisor absolute = 0 := by
  cases sign : row.cSign with
  | false =>
      simp only [
        compareDiffField,
        sign,
        boolM31,
        M31.zero_mul,
        M31.sub_zero,
        M31.one_mul,
      ] at equation
      have equal :=
        byteEqOfFieldEq divisor absolute
          ((M31.sub_eq_zero_iff _ _).mp equation)
      simp [divCompareDiff, sign, equal]
  | true =>
      simp only [
        compareDiffField,
        sign,
        boolM31,
        M31.one_mul,
      ] at equation
      have factor :
          (1 : M31) - M31.reduce 2 =
            M31.reduce (M31.modulus - 1) := by
        decide
      rw [factor] at equation
      have square :
          M31.reduce (M31.modulus - 1) *
              M31.reduce (M31.modulus - 1) =
            1 := by
        decide
      have negated :=
        congrArg
          (fun value : M31 =>
            M31.reduce (M31.modulus - 1) * value)
          equation
      change
        M31.reduce (M31.modulus - 1) *
              (M31.reduce (M31.modulus - 1) *
                (bitVecM31 divisor - bitVecM31 absolute)) =
          M31.reduce (M31.modulus - 1) * 0 at negated
      rw [
        ← MulhDiv.m31MulAssoc,
        square,
        M31.one_mul,
        M31.mul_zero,
      ] at negated
      have equal :=
        byteEqOfFieldEq divisor absolute
          ((M31.sub_eq_zero_iff _ _).mp negated)
      simp [divCompareDiff, sign, equal]

private theorem compareMarkerOfField
    (row : Row)
    (divisor absolute : Byte)
    (upper : (M31.reduce row.ltDiff).val ≤ 1048576)
    (equation :
      M31.reduce row.ltDiff =
        compareDiffField row divisor absolute) :
    ((M31.reduce row.ltDiff).val : Int) =
      divCompareDiff row divisor absolute := by
  have divisorImage :
      (bitVecM31 divisor).val = divisor.toNat :=
    M31.reduce_val_of_lt _ (byteBound divisor)
  have absoluteImage :
      (bitVecM31 absolute).val = absolute.toNat :=
    M31.reduce_val_of_lt _ (byteBound absolute)
  cases sign : row.cSign with
  | false =>
      simp only [
        compareDiffField,
        sign,
        boolM31,
        M31.zero_mul,
        M31.sub_zero,
        M31.one_mul,
      ] at equation
      by_cases ordered : absolute.toNat ≤ divisor.toNat
      · have fieldOrdered :
            (bitVecM31 absolute).val ≤
              (bitVecM31 divisor).val := by
          rw [divisorImage, absoluteImage]
          exact ordered
        have difference :=
          M31.sub_val_of_le
            (bitVecM31 divisor) (bitVecM31 absolute) fieldOrdered
        rw [divisorImage, absoluteImage] at difference
        have values := congrArg M31.val equation
        rw [difference] at values
        simp only [divCompareDiff, sign, Bool.false_eq_true, reduceIte]
        calc
          ((M31.reduce row.ltDiff).val : Int) =
              ((divisor.toNat - absolute.toNat : Nat) : Int) := by
            exact_mod_cast values
          _ = (divisor.toNat : Int) - (absolute.toNat : Int) := by
            omega
      · have reverse : divisor.toNat < absolute.toNat := by omega
        have fieldReverse :
            (bitVecM31 divisor).val <
              (bitVecM31 absolute).val := by
          rw [divisorImage, absoluteImage]
          exact reverse
        have wrapped :=
          M31.sub_val_of_lt
            (bitVecM31 divisor) (bitVecM31 absolute) fieldReverse
        rw [divisorImage, absoluteImage] at wrapped
        have values := congrArg M31.val equation
        rw [wrapped] at values
        have absoluteBound := byteLt256 absolute
        rw [M31.modulus_eq] at values
        omega
  | true =>
      simp only [
        compareDiffField,
        sign,
        boolM31,
        M31.one_mul,
      ] at equation
      have factor :
          (1 : M31) - M31.reduce 2 =
            M31.reduce (M31.modulus - 1) := by
        decide
      rw [factor] at equation
      by_cases equal : divisor.toNat = absolute.toNat
      · have bytesEqual : divisor = absolute :=
          BitVec.eq_of_toNat_eq equal
        subst absolute
        rw [M31.sub_self, M31.mul_zero] at equation
        have values := congrArg M31.val equation
        change (M31.reduce row.ltDiff).val = 0 at values
        simp only [divCompareDiff, sign, reduceIte, Int.sub_self]
        exact_mod_cast values
      · by_cases ordered : divisor.toNat < absolute.toNat
        · let gap := absolute.toNat - divisor.toNat
          have gapPositive : 0 < gap := by
            dsimp [gap]
            omega
          have gapBound : gap < M31.modulus := by
            have absoluteBound := byteLt256 absolute
            rw [M31.modulus_eq]
            dsimp [gap]
            omega
          have differenceField :
              bitVecM31 divisor - bitVecM31 absolute =
                M31.reduce (M31.modulus - gap) := by
            apply M31.ext
            have fieldOrder :
                (bitVecM31 divisor).val <
                  (bitVecM31 absolute).val := by
              rw [divisorImage, absoluteImage]
              exact ordered
            rw [
              M31.sub_val_of_lt _ _ fieldOrder,
              divisorImage,
              absoluteImage,
              M31.reduce_val_of_lt
                (M31.modulus - gap) (by omega),
            ]
            dsimp [gap]
            omega
          rw [
            differenceField,
            m31Negate gap gapBound,
          ] at equation
          have values := congrArg M31.val equation
          rw [M31.reduce_val_of_lt gap gapBound] at values
          simp [divCompareDiff, sign]
          dsimp [gap] at values
          omega
        · have reverse : absolute.toNat < divisor.toNat := by omega
          let gap := divisor.toNat - absolute.toNat
          have gapPositive : 0 < gap := by
            dsimp [gap]
            omega
          have gapBound : gap < M31.modulus := by
            have divisorBound := byteLt256 divisor
            rw [M31.modulus_eq]
            dsimp [gap]
            omega
          have differenceField :
              bitVecM31 divisor - bitVecM31 absolute =
                M31.reduce gap := by
            unfold bitVecM31
            rw [m31ReduceSubOfLe _ _ (by omega)]
          have square :
              M31.reduce (M31.modulus - 1) *
                  M31.reduce (M31.modulus - 1) =
                1 := by
            decide
          have doubleNegation :=
            congrArg
              (fun value : M31 =>
                M31.reduce (M31.modulus - 1) * value)
              (m31Negate gap gapBound)
          change
            M31.reduce (M31.modulus - 1) *
                  (M31.reduce (M31.modulus - 1) *
                    M31.reduce (M31.modulus - gap)) =
              M31.reduce (M31.modulus - 1) *
                M31.reduce gap at doubleNegation
          rw [
            ← MulhDiv.m31MulAssoc,
            square,
            M31.one_mul,
          ] at doubleNegation
          have negativeGap :
              M31.reduce (M31.modulus - 1) * M31.reduce gap =
                M31.reduce (M31.modulus - gap) :=
            doubleNegation.symm
          rw [differenceField, negativeGap] at equation
          have remainderBound :
              M31.modulus - gap < M31.modulus := by
            omega
          have values := congrArg M31.val equation
          rw [
            M31.reduce_val_of_lt
              (M31.modulus - gap) remainderBound,
          ] at values
          have ltValue :
              (M31.reduce row.ltDiff).val =
                M31.modulus - gap := by
            exact values
          rw [ltValue] at upper
          have divisorBound := byteLt256 divisor
          rw [M31.modulus_eq] at upper
          dsimp [gap] at upper
          omega

private theorem scanTotalOfEquations
    (row : Row)
    (activeOne : activeField row = 1)
    (equation : activeField row * (1 - prefix0Field row) = 0) :
    row.zeroDivisor.toNat + row.rZero.toNat +
        row.ltMarker3.toNat + row.ltMarker2.toNat +
        row.ltMarker1.toNat + row.ltMarker0.toNat = 1 := by
  rw [activeOne, M31.one_mul] at equation
  cases zeroDivisor : row.zeroDivisor <;>
    cases remainderZero : row.rZero <;>
    cases marker3 : row.ltMarker3 <;>
    cases marker2 : row.ltMarker2 <;>
    cases marker1 : row.ltMarker1 <;>
    cases marker0 : row.ltMarker0 <;>
    simp_all [
      prefix0Field,
      prefix1Field,

      prefix2Field,
      prefix3Field,
      specialField,
      boolM31,
    ] <;>
    revert equation <;>
    decide

structure ScanConsequences (row : Row) : Prop where
  total :
    row.zeroDivisor.toNat + row.rZero.toNat +
        row.ltMarker3.toNat + row.ltMarker2.toNat +
        row.ltMarker1.toNat + row.ltMarker0.toNat = 1
  equal3 :
    row.zeroDivisor = false → row.rZero = false →
      row.ltMarker3 = false →
      divCompareDiff3 row = 0
  equal2 :
    row.zeroDivisor = false → row.rZero = false →
      row.ltMarker3 = false → row.ltMarker2 = false →
      divCompareDiff2 row = 0
  equal1 :
    row.zeroDivisor = false → row.rZero = false →
      row.ltMarker3 = false → row.ltMarker2 = false →
      row.ltMarker1 = false →
      divCompareDiff1 row = 0
  equal0 :
    row.zeroDivisor = false → row.rZero = false →
      row.ltMarker3 = false → row.ltMarker2 = false →
      row.ltMarker1 = false → row.ltMarker0 = false →
      divCompareDiff0 row = 0
  marker3 :
    row.ltMarker3 = true →
      ((M31.reduce row.ltDiff).val : Int) = divCompareDiff3 row
  marker2 :
    row.ltMarker2 = true →
      ((M31.reduce row.ltDiff).val : Int) = divCompareDiff2 row
  marker1 :
    row.ltMarker1 = true →
      ((M31.reduce row.ltDiff).val : Int) = divCompareDiff1 row
  marker0 :
    row.ltMarker0 = true →
      ((M31.reduce row.ltDiff).val : Int) = divCompareDiff0 row

private theorem scanConsequences
    (selector : Selector)
    (row : Row)
    (witness : Witness row)
    (selectors : SelectorConsequences selector row)
    (equations : DirectEquations row witness)
    (fixed : FixedSemanticConsequences row) :
    ScanConsequences row := by
  have total :=
    scanTotalOfEquations row selectors.activeOne equations.f.scanTotal
  exact {
    total := total
    equal3 := by
      intro zeroDivisor remainderZero marker3
      have equation := equations.e.scanEqual3
      simp only [
        prefix3Field,
        specialField,
        zeroDivisor,
        remainderZero,
        marker3,
        boolM31,
        M31.zero_add,
        M31.sub_zero,
        M31.one_mul,
      ] at equation
      exact
        compareDiffZeroOfField row
          row.rs2Next.limb3 row.remainderAbs.limb3 equation
    equal2 := by
      intro zeroDivisor remainderZero marker3 marker2
      have equation := equations.e.scanEqual2
      simp only [
        prefix2Field,
        prefix3Field,
        specialField,
        zeroDivisor,
        remainderZero,
        marker3,
        marker2,
        boolM31,
        M31.zero_add,
        M31.sub_zero,
        M31.one_mul,
      ] at equation
      exact
        compareDiffZeroOfField row
          row.rs2Next.limb2 row.remainderAbs.limb2 equation
    equal1 := by
      intro zeroDivisor remainderZero marker3 marker2 marker1
      have equation := equations.f.scanEqual1
      simp only [
        prefix1Field,
        prefix2Field,
        prefix3Field,
        specialField,
        zeroDivisor,
        remainderZero,
        marker3,
        marker2,
        marker1,
        boolM31,
        M31.zero_add,
        M31.sub_zero,
        M31.one_mul,
      ] at equation
      exact
        compareDiffZeroOfField row
          row.rs2Next.limb1 row.remainderAbs.limb1 equation
    equal0 := by
      intro zeroDivisor remainderZero marker3 marker2 marker1 marker0
      have equation := equations.f.scanEqual0
      simp only [
        prefix0Field,
        prefix1Field,
        prefix2Field,
        prefix3Field,
        specialField,
        zeroDivisor,
        remainderZero,
        marker3,
        marker2,
        marker1,
        marker0,
        boolM31,
        M31.zero_add,
        M31.sub_zero,
        M31.one_mul,
      ] at equation
      exact
        compareDiffZeroOfField row
          row.rs2Next.limb0 row.remainderAbs.limb0 equation
    marker3 := by
      intro marker
      have zeroDivisor : row.zeroDivisor = false := by
        cases value : row.zeroDivisor <;>
          simp_all <;>
          omega
      have remainderZero : row.rZero = false := by
        cases value : row.rZero <;>
          simp_all <;>
          omega
      have equation := equations.e.scanMarker3
      rw [marker] at equation
      simp only [boolM31, M31.one_mul] at equation
      exact
        compareMarkerOfField row
          row.rs2Next.limb3 row.remainderAbs.limb3
          (fixed.ltDiffUpper zeroDivisor remainderZero)
          ((M31.sub_eq_zero_iff _ _).mp equation)
    marker2 := by
      intro marker
      have zeroDivisor : row.zeroDivisor = false := by
        cases value : row.zeroDivisor <;>
          simp_all <;>
          omega
      have remainderZero : row.rZero = false := by
        cases value : row.rZero <;>
          simp_all <;>
          omega
      have equation := equations.f.scanMarker2
      rw [marker] at equation
      simp only [boolM31, M31.one_mul] at equation
      exact
        compareMarkerOfField row
          row.rs2Next.limb2 row.remainderAbs.limb2
          (fixed.ltDiffUpper zeroDivisor remainderZero)
          ((M31.sub_eq_zero_iff _ _).mp equation)
    marker1 := by
      intro marker
      have zeroDivisor : row.zeroDivisor = false := by
        cases value : row.zeroDivisor <;>
          simp_all <;>
          omega
      have remainderZero : row.rZero = false := by
        cases value : row.rZero <;>
          simp_all <;>
          omega
      have equation := equations.f.scanMarker1
      rw [marker] at equation
      simp only [boolM31, M31.one_mul] at equation
      exact
        compareMarkerOfField row
          row.rs2Next.limb1 row.remainderAbs.limb1
          (fixed.ltDiffUpper zeroDivisor remainderZero)
          ((M31.sub_eq_zero_iff _ _).mp equation)
    marker0 := by
      intro marker
      have zeroDivisor : row.zeroDivisor = false := by
        cases value : row.zeroDivisor <;>
          simp_all <;>
          omega
      have remainderZero : row.rZero = false := by
        cases value : row.rZero <;>
          simp_all <;>
          omega
      have equation := equations.f.scanMarker0
      rw [marker] at equation
      simp only [boolM31, M31.one_mul] at equation
      exact
        compareMarkerOfField row
          row.rs2Next.limb0 row.remainderAbs.limb0
          (fixed.ltDiffUpper zeroDivisor remainderZero)
          ((M31.sub_eq_zero_iff _ _).mp equation)
  }

set_option maxRecDepth 30000 in
theorem acceptedAir_implies_holds
    (selector : Selector)
    (row : Row)
    (witness : Witness row)
    (relationHolds : EvaluatedLookup → Prop)
    (accepted : Acceptance selector row witness relationHolds)
    (admission : Admission row) :
    DivHolds (normalize row) := by
  have selectors :=
    selectorConsequences selector row witness
      accepted.activeProductionRow accepted.directConstraints
  have equations :=
    directEquations selector row witness
      accepted.directConstraints
  have direct :=
    directConsequences selector row witness selectors equations
  have fixedRequests :=
    fixedBoundsOfAcceptance selector row witness selectors
      accepted.fixedTableRequests
  have fixed :=
    fixedSemanticConsequences selector row admission
      selectors fixedRequests
  have scan :=
    scanConsequences selector row witness selectors equations fixed
  refine {
    selectorUnique := by
      simpa using selectors.selectorUnique
    specialExclusive := by
      simpa using direct.specialExclusive
    zeroDivisorLimb0 := by
      simpa using direct.zeroDivisorLimb0
    zeroDivisorLimb1 := by
      simpa using direct.zeroDivisorLimb1
    zeroDivisorLimb2 := by
      simpa using direct.zeroDivisorLimb2
    zeroDivisorLimb3 := by
      simpa using direct.zeroDivisorLimb3
    zeroDivisorQuotient0 := by
      simpa using direct.zeroDivisorQuotient0
    zeroDivisorQuotient1 := by
      simpa using direct.zeroDivisorQuotient1
    zeroDivisorQuotient2 := by
      simpa using direct.zeroDivisorQuotient2
    zeroDivisorQuotient3 := by
      simpa using direct.zeroDivisorQuotient3
    divisorNonzero := by
      simpa using direct.divisorNonzero
    remainderZeroLimb0 := by
      simpa using direct.remainderZeroLimb0
    remainderZeroLimb1 := by
      simpa using direct.remainderZeroLimb1
    remainderZeroLimb2 := by
      simpa using direct.remainderZeroLimb2
    remainderZeroLimb3 := by
      simpa using direct.remainderZeroLimb3
    remainderNonzero := by
      simpa using direct.remainderNonzero
    unsignedDividendSign := by
      simpa using direct.unsignedDividendSign
    unsignedDivisorSign := by
      simpa using direct.unsignedDivisorSign
    signXorDefinition := by
      simpa using direct.signXorDefinition
    quotientSignMatches := by
      simpa using direct.quotientSignMatches
    quotientSignImpliesXor := by
      simpa using direct.quotientSignImpliesXor
    zeroDivisorQuotientSign := by
      simpa using direct.zeroDivisorQuotientSign
    absSameLimb0 := by
      simpa using direct.absSameLimb0
    absSameLimb1 := by
      simpa using direct.absSameLimb1
    absSameLimb2 := by
      simpa using direct.absSameLimb2
    absSameLimb3 := by
      simpa using direct.absSameLimb3
    negationRecurrence := by
      simpa using
        negationRecurrenceOfEquations row witness equations
    productRecurrence :=
      productRecurrenceOfFixed row fixed
    dividendSignBit := by
      simpa using fixed.dividendSignBit
    divisorSignBit := by
      simpa using fixed.divisorSignBit
    quotientSignBit := by
      simpa using fixed.quotientSignBit
    scanTotal := by
      simpa using scan.total
    scanEqual3 := by
      simpa using scan.equal3
    scanEqual2 := by
      simpa using scan.equal2
    scanEqual1 := by
      simpa using scan.equal1
    scanEqual0 := by
      simpa using scan.equal0
    scanMarker3 := by
      simpa using scan.marker3
    scanMarker2 := by
      simpa using scan.marker2
    scanMarker1 := by
      simpa using scan.marker1
    scanMarker0 := by
      simpa using scan.marker0
    ltDiffLower := by
      simpa using fixed.ltDiffLower
    ltDiffUpper := by
      simpa using fixed.ltDiffUpper
    destinationFlag := by
      simpa using direct.destinationFlag
    destinationLimb0 := by
      simpa using direct.destinationLimb0
    destinationLimb1 := by
      simpa using direct.destinationLimb1
    destinationLimb2 := by
      simpa using direct.destinationLimb2
    destinationLimb3 := by
      simpa using direct.destinationLimb3
    sourceOneLimb0 := by
      simpa using congrArg WordBytes.limb0 direct.sourceOne
    sourceOneLimb1 := by
      simpa using congrArg WordBytes.limb1 direct.sourceOne
    sourceOneLimb2 := by
      simpa using congrArg WordBytes.limb2 direct.sourceOne
    sourceOneLimb3 := by
      simpa using congrArg WordBytes.limb3 direct.sourceOne
    sourceTwoLimb0 := by
      simpa using congrArg WordBytes.limb0 direct.sourceTwo
    sourceTwoLimb1 := by
      simpa using congrArg WordBytes.limb1 direct.sourceTwo
    sourceTwoLimb2 := by
      simpa using congrArg WordBytes.limb2 direct.sourceTwo
    sourceTwoLimb3 := by
      simpa using congrArg WordBytes.limb3 direct.sourceTwo
    clockPositive := by
      simpa using admission.clockPositive
    sourceOneClock := by
      simpa using fixed.sourceOneClock
    sourceTwoClock := by
      simpa using fixed.sourceTwoClock
    destinationClock := by
      simpa using fixed.destinationClock
    nextPcResult := by
      simpa only [normalize_pc] using normalize_claimedNextPc row
  }

theorem div_programIdentity :
    Programs.div.source.opcodeSelector.manifestId = 41 ∧
      Programs.div.source.opcodeSelector.mnemonic = "div" ∧

      Programs.div.source.family = .div ∧
      Programs.div.source.contentDigest =
        "3578197a291d77a20c0cf83b2a9ce56fc0b1b215202f1e1a4f0aaed459a745db" :=
  ⟨rfl, rfl, rfl, rfl⟩

theorem divu_programIdentity :
    Programs.divu.source.opcodeSelector.manifestId = 42 ∧
      Programs.divu.source.opcodeSelector.mnemonic = "divu" ∧
      Programs.divu.source.family = .div ∧
      Programs.divu.source.contentDigest =
        "001ccdea48c186c876a8dce9e6b1360981d6fc385c76e3f5f0c86e918f014f87" :=
  ⟨rfl, rfl, rfl, rfl⟩

theorem rem_programIdentity :
    Programs.rem.source.opcodeSelector.manifestId = 43 ∧
      Programs.rem.source.opcodeSelector.mnemonic = "rem" ∧
      Programs.rem.source.family = .div ∧
      Programs.rem.source.contentDigest =
        "1861fc303d92601104effcd0380f26c53d82053a4275a1bdb345b152369e20d8" :=
  ⟨rfl, rfl, rfl, rfl⟩

theorem remu_programIdentity :
    Programs.remu.source.opcodeSelector.manifestId = 44 ∧
      Programs.remu.source.opcodeSelector.mnemonic = "remu" ∧
      Programs.remu.source.family = .div ∧
      Programs.remu.source.contentDigest =
        "9a4b272cf1dce095ebdd30d2658c3cacb58f01b01f0aa002361ab5b1c351c419" :=
  ⟨rfl, rfl, rfl, rfl⟩

structure SelectorAdmission
    (selector : Selector)
    (row : Row)
    (published : TeamB.Selector)
    (selectedProgram : LocalProgram)
    (manifestId : Nat)
    (mnemonic digest : String) : Prop where
  rowSelected :
    match selector with
    | .div =>
        row.isDiv = true ∧ row.isDivu = false ∧
          row.isRem = false ∧ row.isRemu = false
    | .divu =>
        row.isDiv = false ∧ row.isDivu = true ∧
          row.isRem = false ∧ row.isRemu = false
    | .rem =>
        row.isDiv = false ∧ row.isDivu = false ∧
          row.isRem = true ∧ row.isRemu = false
    | .remu =>
        row.isDiv = false ∧ row.isDivu = false ∧
          row.isRem = false ∧ row.isRemu = true
  exactProgram : program selector = selectedProgram
  manifest :
    selectedProgram.source.opcodeSelector.manifestId = manifestId
  publishedManifest :
    manifestId = TeamB.Selector.manifestId published
  programMnemonic :
    selectedProgram.source.opcodeSelector.mnemonic = mnemonic
  publishedMnemonic :
    mnemonic = TeamB.Selector.mnemonic published
  unique :
    ∀ candidate : TeamB.Selector,
      TeamB.Selector.manifestId candidate = manifestId →
        candidate = published
  familyAdmits :
    selectedProgram.source.family.validOpcode manifestId mnemonic = true
  universalIdentity :
    Publication.actualProgramIdentities[manifestId]? =
      some {
        manifestId := manifestId
        mnemonic := mnemonic
        family := selectedProgram.source.family
        contentDigest := digest
      }

private theorem selectorAdmissionUnique
    (published : TeamB.Selector)
    (manifestId : Nat)
    (identity :
      TeamB.Selector.manifestId published = manifestId) :
    ∀ candidate : TeamB.Selector,
      TeamB.Selector.manifestId candidate = manifestId →
        candidate = published := by
  intro candidate same
  apply TeamB.Selector.manifestId_injective
  rw [identity]
  exact same

theorem div_selectorAdmission
    (row : Row)
    (selected :
      row.isDiv = true ∧ row.isDivu = false ∧
        row.isRem = false ∧ row.isRemu = false) :
    SelectorAdmission .div row .div Programs.div 41 "div"
      "3578197a291d77a20c0cf83b2a9ce56fc0b1b215202f1e1a4f0aaed459a745db" := by
  refine {
    rowSelected := selected
    exactProgram := rfl
    manifest := rfl
    publishedManifest := rfl
    programMnemonic := rfl
    publishedMnemonic := rfl
    unique := selectorAdmissionUnique .div 41 rfl
    familyAdmits := by decide
    universalIdentity := ?_
  }
  rw [Publication.exactProductionProgramIdentities]
  rfl

theorem divu_selectorAdmission
    (row : Row)
    (selected :
      row.isDiv = false ∧ row.isDivu = true ∧
        row.isRem = false ∧ row.isRemu = false) :
    SelectorAdmission .divu row .divu Programs.divu 42 "divu"
      "001ccdea48c186c876a8dce9e6b1360981d6fc385c76e3f5f0c86e918f014f87" := by
  refine {
    rowSelected := selected
    exactProgram := rfl
    manifest := rfl
    publishedManifest := rfl
    programMnemonic := rfl
    publishedMnemonic := rfl
    unique := selectorAdmissionUnique .divu 42 rfl
    familyAdmits := by decide
    universalIdentity := ?_
  }
  rw [Publication.exactProductionProgramIdentities]
  rfl

theorem rem_selectorAdmission
    (row : Row)
    (selected :
      row.isDiv = false ∧ row.isDivu = false ∧
        row.isRem = true ∧ row.isRemu = false) :
    SelectorAdmission .rem row .rem Programs.rem 43 "rem"
      "1861fc303d92601104effcd0380f26c53d82053a4275a1bdb345b152369e20d8" := by
  refine {
    rowSelected := selected
    exactProgram := rfl
    manifest := rfl
    publishedManifest := rfl
    programMnemonic := rfl
    publishedMnemonic := rfl
    unique := selectorAdmissionUnique .rem 43 rfl
    familyAdmits := by decide
    universalIdentity := ?_
  }
  rw [Publication.exactProductionProgramIdentities]
  rfl

theorem remu_selectorAdmission
    (row : Row)
    (selected :
      row.isDiv = false ∧ row.isDivu = false ∧
        row.isRem = false ∧ row.isRemu = true) :
    SelectorAdmission .remu row .remu Programs.remu 44 "remu"
      "9a4b272cf1dce095ebdd30d2658c3cacb58f01b01f0aa002361ab5b1c351c419" := by
  refine {
    rowSelected := selected
    exactProgram := rfl
    manifest := rfl
    publishedManifest := rfl
    programMnemonic := rfl
    publishedMnemonic := rfl
    unique := selectorAdmissionUnique .remu 44 rfl
    familyAdmits := by decide
    universalIdentity := ?_
  }
  rw [Publication.exactProductionProgramIdentities]
  rfl

private theorem selectedAcceptance_is_generic
    (selector : Selector)
    (row : Row)
    (witness : Witness row)
    (relationHolds : EvaluatedLookup → Prop)
    (accepted :
      Publication.AcceptedProductionEvaluation
        ((program selector).evalSymbolic (columns row witness))
        relationHolds) :
    Acceptance selector row witness relationHolds := by
  simpa only [evaluation] using accepted

/-
Stable publication wrapper for manifest selector 41 (`DIV`).  The premise is
the exact generated `Programs.div` evaluation; the row selector is recovered
from that acceptance rather than supplied by the caller.
-/
set_option maxRecDepth 30000 in
theorem div_accepted_air_implies_retirement
    (row : Row)
    (witness : Witness row)
    (environment : Opcodes.DivEnvironment row)
    (relationHolds : EvaluatedLookup → Prop)
    (accepted :
      Publication.AcceptedProductionEvaluation
        (Programs.div.evalSymbolic (columns row witness))
        relationHolds)
    (admission : Admission row) :
    SelectorAdmission .div row .div Programs.div 41 "div"
        "3578197a291d77a20c0cf83b2a9ce56fc0b1b215202f1e1a4f0aaed459a745db" ∧
      DivHolds (normalize row) ∧
      divRetirement (normalize row) =
        Sail.Reviewed.executeDiv
          environment.pre.pc row.rd
          (environment.pre.registers row.rs1)
          (environment.pre.registers row.rs2) ∧
      ExactTupleProjection .div row witness ∧
      ExactFixedProjection .div row witness ∧
      (∀ lookup,
        lookup ∈
            (Programs.div.evalSymbolic
              (columns row witness)).liveLookups →
          lookup.tableId = none →
          relationHolds lookup) := by
  have generic : Acceptance .div row witness relationHolds :=
    selectedAcceptance_is_generic .div row witness relationHolds
      (by simpa [program] using accepted)
  have selectors :=
    selectorConsequences .div row witness
      generic.activeProductionRow generic.directConstraints
  have holds :=
    acceptedAir_implies_holds
      .div row witness relationHolds generic admission
  have normalizedSelector : (normalize row).isDiv = true := by
    simpa using selectors.selected.1
  have retirement :=
    Opcodes.div_retires_as_reviewed
      (normalize row) (normalizeEnvironment row environment)
      holds normalizedSelector
  have reviewedRetirement :
    divRetirement (normalize row) =
      Sail.Reviewed.executeDiv
        environment.pre.pc row.rd
        (environment.pre.registers row.rs1)
        (environment.pre.registers row.rs2) := by
    simpa only [normalize_rd, normalize_rs1, normalize_rs2] using retirement
  exact
    ⟨div_selectorAdmission row selectors.selected,
      holds, reviewedRetirement,
      exactTupleProjection .div row witness,
      exactFixedProjection .div row witness,
      accepted.liveRelations⟩

/- Stable publication wrapper for manifest selector 42 (`DIVU`). -/
set_option maxRecDepth 30000 in
theorem divu_accepted_air_implies_retirement
    (row : Row)
    (witness : Witness row)
    (environment : Opcodes.DivEnvironment row)
    (relationHolds : EvaluatedLookup → Prop)
    (accepted :
      Publication.AcceptedProductionEvaluation
        (Programs.divu.evalSymbolic (columns row witness))
        relationHolds)
    (admission : Admission row) :
    SelectorAdmission .divu row .divu Programs.divu 42 "divu"
        "001ccdea48c186c876a8dce9e6b1360981d6fc385c76e3f5f0c86e918f014f87" ∧
      DivHolds (normalize row) ∧
      divRetirement (normalize row) =
        Sail.Reviewed.executeDivu
          environment.pre.pc row.rd
          (environment.pre.registers row.rs1)
          (environment.pre.registers row.rs2) ∧
      ExactTupleProjection .divu row witness ∧
      ExactFixedProjection .divu row witness ∧
      (∀ lookup,
        lookup ∈
            (Programs.divu.evalSymbolic
              (columns row witness)).liveLookups →
          lookup.tableId = none →
          relationHolds lookup) := by
  have generic : Acceptance .divu row witness relationHolds :=
    selectedAcceptance_is_generic .divu row witness relationHolds
      (by simpa [program] using accepted)
  have selectors :=
    selectorConsequences .divu row witness
      generic.activeProductionRow generic.directConstraints
  have holds :=
    acceptedAir_implies_holds
      .divu row witness relationHolds generic admission
  have normalizedSelector : (normalize row).isDivu = true := by
    simpa using selectors.selected.2.1
  have retirement :=
    Opcodes.divu_retires_as_reviewed
      (normalize row) (normalizeEnvironment row environment)
      holds normalizedSelector
  have reviewedRetirement :
    divRetirement (normalize row) =
      Sail.Reviewed.executeDivu
        environment.pre.pc row.rd
        (environment.pre.registers row.rs1)
        (environment.pre.registers row.rs2) := by
    simpa only [normalize_rd, normalize_rs1, normalize_rs2] using retirement
  exact
    ⟨divu_selectorAdmission row selectors.selected,
      holds, reviewedRetirement,
      exactTupleProjection .divu row witness,
      exactFixedProjection .divu row witness,
      accepted.liveRelations⟩

/- Stable publication wrapper for manifest selector 43 (`REM`). -/
set_option maxRecDepth 30000 in
theorem rem_accepted_air_implies_retirement
    (row : Row)
    (witness : Witness row)
    (environment : Opcodes.DivEnvironment row)
    (relationHolds : EvaluatedLookup → Prop)
    (accepted :
      Publication.AcceptedProductionEvaluation
        (Programs.rem.evalSymbolic (columns row witness))
        relationHolds)
    (admission : Admission row) :
    SelectorAdmission .rem row .rem Programs.rem 43 "rem"
        "1861fc303d92601104effcd0380f26c53d82053a4275a1bdb345b152369e20d8" ∧
      DivHolds (normalize row) ∧
      divRetirement (normalize row) =
        Sail.Reviewed.executeRem
          environment.pre.pc row.rd
          (environment.pre.registers row.rs1)
          (environment.pre.registers row.rs2) ∧
      ExactTupleProjection .rem row witness ∧
      ExactFixedProjection .rem row witness ∧
      (∀ lookup,
        lookup ∈
            (Programs.rem.evalSymbolic
              (columns row witness)).liveLookups →
          lookup.tableId = none →
          relationHolds lookup) := by
  have generic : Acceptance .rem row witness relationHolds :=
    selectedAcceptance_is_generic .rem row witness relationHolds
      (by simpa [program] using accepted)
  have selectors :=
    selectorConsequences .rem row witness
      generic.activeProductionRow generic.directConstraints
  have holds :=
    acceptedAir_implies_holds
      .rem row witness relationHolds generic admission
  have normalizedSelector : (normalize row).isRem = true := by
    simpa using selectors.selected.2.2.1
  have retirement :=
    Opcodes.rem_retires_as_reviewed
      (normalize row) (normalizeEnvironment row environment)
      holds normalizedSelector
  have reviewedRetirement :
    divRetirement (normalize row) =
      Sail.Reviewed.executeRem
        environment.pre.pc row.rd
        (environment.pre.registers row.rs1)
        (environment.pre.registers row.rs2) := by

    simpa only [normalize_rd, normalize_rs1, normalize_rs2] using retirement
  exact
    ⟨rem_selectorAdmission row selectors.selected,
      holds, reviewedRetirement,
      exactTupleProjection .rem row witness,
      exactFixedProjection .rem row witness,
      accepted.liveRelations⟩

/- Stable publication wrapper for manifest selector 44 (`REMU`). -/
set_option maxRecDepth 30000 in
theorem remu_accepted_air_implies_retirement
    (row : Row)
    (witness : Witness row)
    (environment : Opcodes.DivEnvironment row)
    (relationHolds : EvaluatedLookup → Prop)
    (accepted :
      Publication.AcceptedProductionEvaluation
        (Programs.remu.evalSymbolic (columns row witness))
        relationHolds)
    (admission : Admission row) :
    SelectorAdmission .remu row .remu Programs.remu 44 "remu"
        "9a4b272cf1dce095ebdd30d2658c3cacb58f01b01f0aa002361ab5b1c351c419" ∧
      DivHolds (normalize row) ∧
      divRetirement (normalize row) =
        Sail.Reviewed.executeRemu
          environment.pre.pc row.rd
          (environment.pre.registers row.rs1)
          (environment.pre.registers row.rs2) ∧
      ExactTupleProjection .remu row witness ∧
      ExactFixedProjection .remu row witness ∧
      (∀ lookup,
        lookup ∈
            (Programs.remu.evalSymbolic
              (columns row witness)).liveLookups →
          lookup.tableId = none →
          relationHolds lookup) := by
  have generic : Acceptance .remu row witness relationHolds :=
    selectedAcceptance_is_generic .remu row witness relationHolds
      (by simpa [program] using accepted)
  have selectors :=
    selectorConsequences .remu row witness
      generic.activeProductionRow generic.directConstraints
  have holds :=
    acceptedAir_implies_holds
      .remu row witness relationHolds generic admission
  have normalizedSelector : (normalize row).isRemu = true := by
    simpa using selectors.selected.2.2.2
  have retirement :=
    Opcodes.remu_retires_as_reviewed
      (normalize row) (normalizeEnvironment row environment)
      holds normalizedSelector
  have reviewedRetirement :
    divRetirement (normalize row) =
      Sail.Reviewed.executeRemu
        environment.pre.pc row.rd
        (environment.pre.registers row.rs1)
        (environment.pre.registers row.rs2) := by
    simpa only [normalize_rd, normalize_rs1, normalize_rs2] using retirement
  exact
    ⟨remu_selectorAdmission row selectors.selected,
      holds, reviewedRetirement,
      exactTupleProjection .remu row witness,
      exactFixedProjection .remu row witness,
      accepted.liveRelations⟩


end Division

end RiscvRefinement.Publication.TeamB.MulhDiv
