import RiscvRefinement.Publication.TeamB.MulhDiv.Division.NegationArithmetic

namespace RiscvRefinement.Publication.TeamB.MulhDiv

open RiscvRefinement
open RiscvRefinement.Air
open RiscvRefinement.Air.Family

namespace Division

private theorem productBoolHighFieldEqReduce (value : Bool) :
    boolM31 value * M31.reduce 255 =
      M31.reduce (255 * value.toNat) := by
  cases value <;> decide

private theorem productRemainderHighFieldEqReduce
    (sign zero : Bool) :
    boolM31 sign * (1 - boolM31 zero) * M31.reduce 255 =
      M31.reduce (255 * (sign && !zero).toNat) := by
  cases sign <;> cases zero <;> decide

theorem productQuotientHighFieldImage (row : Row) :
    quotientHighField row = M31.reduce (divQuotientHigh row) := by
  exact productBoolHighFieldEqReduce row.qSign

theorem productDivisorHighFieldImage (row : Row) :
    divisorHighField row = M31.reduce (divDivisorHigh row) := by
  exact productBoolHighFieldEqReduce row.cSign

theorem productDividendHighFieldImage (row : Row) :
    dividendHighField row = M31.reduce (divDividendHigh row) := by
  exact productBoolHighFieldEqReduce row.bSign

theorem productRemainderHighFieldImage (row : Row) :
    remainderHighField row = M31.reduce (divRemainderHigh row) := by
  exact productRemainderHighFieldEqReduce row.bSign row.rZero

theorem productThreeByteSumCancel
    (a b c d : Byte) :
    bitVecM31 a + bitVecM31 b + bitVecM31 c + bitVecM31 d -
        bitVecM31 d =
      bitVecM31 a + bitVecM31 b + bitVecM31 c := by
  let prefixValue := a.toNat + b.toNat + c.toNat
  have aBound := byteLt256 a
  have bBound := byteLt256 b
  have cBound := byteLt256 c
  have dBound := byteLt256 d
  have prefixBound : prefixValue < M31.modulus := by
    rw [M31.modulus_eq]
    simp only [prefixValue]
    omega
  have dFieldBound : d.toNat < M31.modulus := by
    rw [M31.modulus_eq]
    omega
  have totalBound : prefixValue + d.toNat < M31.modulus := by
    rw [M31.modulus_eq]
    simp only [prefixValue]
    omega
  have prefixImage :
      bitVecM31 a + bitVecM31 b + bitVecM31 c =
        M31.reduce prefixValue := by
    simp only [bitVecM31, prefixValue]
    rw [
      Air.Bridge.TeamACommon.reduceAdd,
      Air.Bridge.TeamACommon.reduceAdd,
    ]
  calc
    bitVecM31 a + bitVecM31 b + bitVecM31 c + bitVecM31 d -
          bitVecM31 d =
        (M31.reduce prefixValue + M31.reduce d.toNat) -
          M31.reduce d.toNat := by
      rw [← prefixImage]
      rfl
    _ = M31.reduce prefixValue :=
      MulhDiv.reduceAddSubCancelOfBound
        prefixValue d.toNat prefixBound dFieldBound totalBound
    _ = bitVecM31 a + bitVecM31 b + bitVecM31 c :=
      prefixImage.symm

set_option maxRecDepth 30000 in
theorem productRecurrence1ConvolutionImage
    (row : Row) :
    M31.reduce (divConv1 row) =
      bitVecM31 row.rs2Next.limb0 *
            bitVecM31 row.quotient.limb1 +
          bitVecM31 row.rs2Next.limb1 *
            bitVecM31 row.quotient.limb0 +
        bitVecM31 row.remainder.limb1 := by
  rw [divConv1]
  rw [
    ← Air.Bridge.TeamACommon.reduceAdd,
    ← Air.Bridge.TeamACommon.reduceAdd,
    ← Air.Bridge.TeamACommon.reduceMul,
    ← Air.Bridge.TeamACommon.reduceMul,
  ]
  rfl

set_option maxRecDepth 30000 in
theorem productRecurrence1AccumulatedImage
    (row : Row) :
    M31.reduce ((carry0Field row).val + divConv1 row) =
      carry0Field row +
          bitVecM31 row.rs2Next.limb0 *
            bitVecM31 row.quotient.limb1 +
        bitVecM31 row.rs2Next.limb1 *
          bitVecM31 row.quotient.limb0 +
        bitVecM31 row.remainder.limb1 := by
  rw [MulhDiv.reduceValAdd, productRecurrence1ConvolutionImage]
  rw [← MulhDiv.m31AddAssoc, ← MulhDiv.m31AddAssoc]

set_option maxRecDepth 30000 in
theorem productRecurrence1FieldEquation
    (row : Row) :
    ((M31.reduce ((carry0Field row).val + divConv1 row) -
          M31.reduce row.rs1Next.limb1.toNat) *
        M31.reduce 8388608).val =
      (carry1Field row).val := by
  apply congrArg M31.val
  rw [carry1Field, productRecurrence1AccumulatedImage]
  rfl

set_option maxRecDepth 30000 in
theorem productRecurrence2ConvolutionImage
    (row : Row) :
    M31.reduce (divConv2 row) =
      bitVecM31 row.rs2Next.limb0 *
              bitVecM31 row.quotient.limb2 +
            bitVecM31 row.rs2Next.limb1 *
              bitVecM31 row.quotient.limb1 +
          bitVecM31 row.rs2Next.limb2 *
            bitVecM31 row.quotient.limb0 +
        bitVecM31 row.remainder.limb2 := by
  rw [divConv2]
  rw [
    ← Air.Bridge.TeamACommon.reduceAdd,
    ← Air.Bridge.TeamACommon.reduceAdd,
    ← Air.Bridge.TeamACommon.reduceAdd,
    ← Air.Bridge.TeamACommon.reduceMul,
    ← Air.Bridge.TeamACommon.reduceMul,
    ← Air.Bridge.TeamACommon.reduceMul,
  ]
  rfl

set_option maxRecDepth 30000 in
theorem productRecurrence2FieldEquation
    (row : Row) :
    ((M31.reduce ((carry1Field row).val + divConv2 row) -
          M31.reduce row.rs1Next.limb2.toNat) *
        M31.reduce 8388608).val =
      (carry2Field row).val := by
  apply congrArg M31.val
  rw [
    carry2Field,
    MulhDiv.reduceValAdd,
    productRecurrence2ConvolutionImage,
  ]
  rw [
    ← MulhDiv.m31AddAssoc,
    ← MulhDiv.m31AddAssoc,
    ← MulhDiv.m31AddAssoc,
  ]
  rfl

set_option maxRecDepth 30000 in
theorem productRecurrence3ConvolutionImage
    (row : Row) :
    M31.reduce (divConv3 row) =
      bitVecM31 row.rs2Next.limb0 *
                bitVecM31 row.quotient.limb3 +
              bitVecM31 row.rs2Next.limb1 *
                bitVecM31 row.quotient.limb2 +
            bitVecM31 row.rs2Next.limb2 *
              bitVecM31 row.quotient.limb1 +
          bitVecM31 row.rs2Next.limb3 *
            bitVecM31 row.quotient.limb0 +
        bitVecM31 row.remainder.limb3 := by
  rw [divConv3]
  rw [
    ← Air.Bridge.TeamACommon.reduceAdd,
    ← Air.Bridge.TeamACommon.reduceAdd,
    ← Air.Bridge.TeamACommon.reduceAdd,
    ← Air.Bridge.TeamACommon.reduceAdd,
    ← Air.Bridge.TeamACommon.reduceMul,
    ← Air.Bridge.TeamACommon.reduceMul,
    ← Air.Bridge.TeamACommon.reduceMul,
    ← Air.Bridge.TeamACommon.reduceMul,
  ]
  rfl

set_option maxRecDepth 30000 in
theorem productRecurrence3FieldEquation
    (row : Row) :
    ((M31.reduce ((carry2Field row).val + divConv3 row) -
          M31.reduce row.rs1Next.limb3.toNat) *
        M31.reduce 8388608).val =
      (carry3Field row).val := by
  apply congrArg M31.val
  rw [
    carry3Field,
    MulhDiv.reduceValAdd,
    productRecurrence3ConvolutionImage,
  ]
  rw [
    ← MulhDiv.m31AddAssoc,
    ← MulhDiv.m31AddAssoc,
    ← MulhDiv.m31AddAssoc,
    ← MulhDiv.m31AddAssoc,
  ]
  rfl

set_option maxRecDepth 30000 in
theorem productRecurrence4ConvolutionImage
    (row : Row) :
    M31.reduce (divConv4 row) =
      bitVecM31 row.rs2Next.limb0 * quotientHighField row +
              bitVecM31 row.rs2Next.limb1 *
                bitVecM31 row.quotient.limb3 +
            bitVecM31 row.rs2Next.limb2 *
              bitVecM31 row.quotient.limb2 +
          bitVecM31 row.rs2Next.limb3 *
            bitVecM31 row.quotient.limb1 +
        divisorHighField row * bitVecM31 row.quotient.limb0 +
        remainderHighField row := by
  rw [divConv4]
  rw [
    ← Air.Bridge.TeamACommon.reduceAdd,
    ← Air.Bridge.TeamACommon.reduceAdd,
    ← Air.Bridge.TeamACommon.reduceAdd,
    ← Air.Bridge.TeamACommon.reduceAdd,
    ← Air.Bridge.TeamACommon.reduceAdd,
    ← Air.Bridge.TeamACommon.reduceMul,
    ← Air.Bridge.TeamACommon.reduceMul,
    ← Air.Bridge.TeamACommon.reduceMul,
    ← Air.Bridge.TeamACommon.reduceMul,
    ← Air.Bridge.TeamACommon.reduceMul,
    ← productQuotientHighFieldImage,
    ← productDivisorHighFieldImage,
    ← productRemainderHighFieldImage,
  ]
  rfl

set_option maxRecDepth 30000 in
theorem productRecurrence4FieldEquation
    (row : Row) :
    ((M31.reduce ((carry3Field row).val + divConv4 row) -
          M31.reduce (divDividendHigh row)) *
        M31.reduce 8388608).val =
      (carry4Field row).val := by
  apply congrArg M31.val
  rw [
    carry4Field,
    MulhDiv.reduceValAdd,
    productRecurrence4ConvolutionImage,
    ← productDividendHighFieldImage,
  ]
  rw [
    ← MulhDiv.m31AddAssoc,
    ← MulhDiv.m31AddAssoc,
    ← MulhDiv.m31AddAssoc,
    ← MulhDiv.m31AddAssoc,
    ← MulhDiv.m31AddAssoc,
  ]

theorem productRecurrence5Regroup
    (row : Row) :
    divConv5 row =
      (row.rs2Next.limb0.toNat + row.rs2Next.limb1.toNat) *
            divQuotientHigh row +
          row.rs2Next.limb2.toNat * row.quotient.limb3.toNat +
        row.rs2Next.limb3.toNat * row.quotient.limb2.toNat +
        divDivisorHigh row *
            (row.quotient.limb0.toNat + row.quotient.limb1.toNat) +
        divRemainderHigh row := by
  simp [divConv5, Nat.add_mul, Nat.mul_add, Nat.add_assoc]

set_option maxRecDepth 30000 in
theorem productRecurrence5ConvolutionImage
    (row : Row) :
    M31.reduce (divConv5 row) =
      (bitVecM31 row.rs2Next.limb0 +
            bitVecM31 row.rs2Next.limb1) *
          quotientHighField row +
        bitVecM31 row.rs2Next.limb2 *
            bitVecM31 row.quotient.limb3 +
          bitVecM31 row.rs2Next.limb3 *
            bitVecM31 row.quotient.limb2 +
        divisorHighField row *
            (bitVecM31 row.quotient.limb0 +
              bitVecM31 row.quotient.limb1) +
        remainderHighField row := by
  rw [productRecurrence5Regroup]
  rw [
    ← Air.Bridge.TeamACommon.reduceAdd,
    ← Air.Bridge.TeamACommon.reduceAdd,
    ← Air.Bridge.TeamACommon.reduceAdd,
    ← Air.Bridge.TeamACommon.reduceAdd,
    ← Air.Bridge.TeamACommon.reduceMul,
    ← Air.Bridge.TeamACommon.reduceMul,
    ← Air.Bridge.TeamACommon.reduceMul,
    ← Air.Bridge.TeamACommon.reduceMul,
    ← Air.Bridge.TeamACommon.reduceAdd,
    ← Air.Bridge.TeamACommon.reduceAdd,
    ← productQuotientHighFieldImage,
    ← productDivisorHighFieldImage,
    ← productRemainderHighFieldImage,
  ]
  rfl

set_option maxRecDepth 30000 in
theorem productRecurrence5FieldEquation
    (row : Row) :
    ((M31.reduce ((carry4Field row).val + divConv5 row) -
          M31.reduce (divDividendHigh row)) *
        M31.reduce 8388608).val =
      (carry5Field row).val := by
  apply congrArg M31.val
  rw [
    carry5Field,
    MulhDiv.reduceValAdd,
    productRecurrence5ConvolutionImage,
    ← productDividendHighFieldImage,
  ]
  rw [
    ← MulhDiv.m31AddAssoc,
    ← MulhDiv.m31AddAssoc,
    ← MulhDiv.m31AddAssoc,
    ← MulhDiv.m31AddAssoc,
  ]

theorem productRecurrence6Regroup
    (row : Row) :
    divConv6 row =
      (row.rs2Next.limb0.toNat + row.rs2Next.limb1.toNat +
            row.rs2Next.limb2.toNat) *
          divQuotientHigh row +
        row.rs2Next.limb3.toNat * row.quotient.limb3.toNat +
        divDivisorHigh row *
            (row.quotient.limb0.toNat + row.quotient.limb1.toNat +
              row.quotient.limb2.toNat) +
        divRemainderHigh row := by
  simp [divConv6, Nat.add_mul, Nat.mul_add, Nat.add_assoc]

set_option maxRecDepth 30000 in
theorem productRecurrence6ConvolutionImage
    (row : Row) :
    M31.reduce (divConv6 row) =
      (bitVecM31 row.rs2Next.limb0 +
              bitVecM31 row.rs2Next.limb1 +
            bitVecM31 row.rs2Next.limb2) *
          quotientHighField row +
        bitVecM31 row.rs2Next.limb3 *
          bitVecM31 row.quotient.limb3 +
        divisorHighField row *
            (bitVecM31 row.quotient.limb0 +
                bitVecM31 row.quotient.limb1 +
              bitVecM31 row.quotient.limb2) +
        remainderHighField row := by
  rw [productRecurrence6Regroup]
  rw [
    ← Air.Bridge.TeamACommon.reduceAdd,
    ← Air.Bridge.TeamACommon.reduceAdd,
    ← Air.Bridge.TeamACommon.reduceAdd,
    ← Air.Bridge.TeamACommon.reduceMul,
    ← Air.Bridge.TeamACommon.reduceMul,
    ← Air.Bridge.TeamACommon.reduceMul,
    ← Air.Bridge.TeamACommon.reduceAdd,
    ← Air.Bridge.TeamACommon.reduceAdd,
    ← Air.Bridge.TeamACommon.reduceAdd,
    ← Air.Bridge.TeamACommon.reduceAdd,
    ← productQuotientHighFieldImage,
    ← productDivisorHighFieldImage,
    ← productRemainderHighFieldImage,
  ]
  rfl

set_option maxRecDepth 30000 in
theorem productRecurrence6FieldEquation
    (row : Row) :
    ((M31.reduce ((carry5Field row).val + divConv6 row) -
          M31.reduce (divDividendHigh row)) *
        M31.reduce 8388608).val =
      (carry6Field row).val := by
  apply congrArg M31.val
  rw [
    carry6Field,
    productThreeByteSumCancel
      row.rs2Next.limb0 row.rs2Next.limb1
      row.rs2Next.limb2 row.rs2Next.limb3,
    productThreeByteSumCancel
      row.quotient.limb0 row.quotient.limb1
      row.quotient.limb2 row.quotient.limb3,
    MulhDiv.reduceValAdd,
    productRecurrence6ConvolutionImage,
    ← productDividendHighFieldImage,
  ]
  rw [
    ← MulhDiv.m31AddAssoc,
    ← MulhDiv.m31AddAssoc,
    ← MulhDiv.m31AddAssoc,
  ]

theorem productRecurrence7Regroup
    (row : Row) :
    divConv7 row =
      (row.rs2Next.limb0.toNat + row.rs2Next.limb1.toNat +
              row.rs2Next.limb2.toNat + row.rs2Next.limb3.toNat) *
          divQuotientHigh row +
        divDivisorHigh row *
            (row.quotient.limb0.toNat + row.quotient.limb1.toNat +
                row.quotient.limb2.toNat + row.quotient.limb3.toNat) +
        divRemainderHigh row := by
  simp [divConv7, Nat.add_mul, Nat.mul_add, Nat.add_assoc]

set_option maxRecDepth 30000 in
theorem productRecurrence7ConvolutionImage
    (row : Row) :
    M31.reduce (divConv7 row) =
      (bitVecM31 row.rs2Next.limb0 +
                bitVecM31 row.rs2Next.limb1 +
              bitVecM31 row.rs2Next.limb2 +
            bitVecM31 row.rs2Next.limb3) *
          quotientHighField row +
        divisorHighField row *
            (bitVecM31 row.quotient.limb0 +
                  bitVecM31 row.quotient.limb1 +
                bitVecM31 row.quotient.limb2 +
              bitVecM31 row.quotient.limb3) +
        remainderHighField row := by
  rw [productRecurrence7Regroup]
  rw [
    ← Air.Bridge.TeamACommon.reduceAdd,
    ← Air.Bridge.TeamACommon.reduceAdd,
    ← Air.Bridge.TeamACommon.reduceMul,
    ← Air.Bridge.TeamACommon.reduceMul,
    ← Air.Bridge.TeamACommon.reduceAdd,
    ← Air.Bridge.TeamACommon.reduceAdd,
    ← Air.Bridge.TeamACommon.reduceAdd,
    ← Air.Bridge.TeamACommon.reduceAdd,
    ← Air.Bridge.TeamACommon.reduceAdd,
    ← Air.Bridge.TeamACommon.reduceAdd,
    ← productQuotientHighFieldImage,
    ← productDivisorHighFieldImage,
    ← productRemainderHighFieldImage,
  ]
  rfl

set_option maxRecDepth 30000 in
theorem productRecurrence7FieldEquation
    (row : Row) :
    ((M31.reduce ((carry6Field row).val + divConv7 row) -
          M31.reduce (divDividendHigh row)) *
        M31.reduce 8388608).val =
      (carry7Field row).val := by
  apply congrArg M31.val
  rw [
    carry7Field,
    MulhDiv.reduceValAdd,
    productRecurrence7ConvolutionImage,
    ← productDividendHighFieldImage,
  ]
  rw [
    ← MulhDiv.m31AddAssoc,
    ← MulhDiv.m31AddAssoc,
  ]

end Division

end RiscvRefinement.Publication.TeamB.MulhDiv
