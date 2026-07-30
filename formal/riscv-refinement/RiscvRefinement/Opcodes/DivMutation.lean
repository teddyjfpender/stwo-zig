-- REVIEWED-CAPSULE BOUNDARY. Hand-written file; not generated, and not a
-- generated-Sail theorem. The architectural conclusions these mutation
-- controls certify are stated via Arith.divideSigned / Arith.divideUnsigned
-- of RiscvRefinement/Arith/Division.lean -- the arithmetic the reviewed
-- normalized capsule RiscvRefinement/Sail/Reviewed/Div.lean fixes, which is
-- hand-written with no generator, no digest, and no derivation from any Sail
-- artifact (see its header). Nothing in this file is publication-level for
-- the architectural side.

import RiscvRefinement.Air.Family.Div
import RiscvRefinement.Mutation
import RiscvRefinement.Opcodes.Div

/-!
# Load-bearing mutation controls for `DIV`, `DIVU`, `REM` and `REMU`

Issue #137 names a publication mutation matrix for the DIV family. This file is
that matrix, in the `MutationControl` form of `RiscvRefinement/Mutation.lean`:
for each named deletion, a copy of `DivHolds` with exactly *one* field removed,
a proof that the deletion really is a weakening, a concrete row that satisfies
everything left, and a proof that the row gets the architectural answer wrong.

Each control is stated against `DivuRetiresQuotient` or `DivRetiresQuotient`
below -- the architectural claim that the word the row emits on the destination
register bus is `Arith.divideUnsigned` / `Arith.divideSigned` of the two words
it consumed on the source buses. That claim is stated purely in terms of
`Arith/Division.lean` and the consumed register values, so no control here can
be circular: none of them restates the constraint it deletes.

Unlike `MultiplyMutation.lean` and `LoadStoreMutation.lean`, the soundness side
is discharged here rather than assumed. `divu_conclusion_sound` and
`div_conclusion_sound` prove the conclusion from the *unweakened* `DivHolds`, so
every `..._is_load_bearing` corollary below is unconditional.
-/

namespace RiscvRefinement.Opcodes

open RiscvRefinement
open RiscvRefinement.Air.Family
open RiscvRefinement.Mutation

/-! ## The architectural conclusions

Both predicates are guarded by the row's own selector, so that soundness can be
stated for every `DivHolds` row at once and the resulting `strictly_weaker`
corollaries need no hypotheses. -/

/-- The architectural claim `divu_refines` reaches on a `DIVU` row: the word
emitted on the destination register bus is the RISC-V unsigned quotient of the
two words consumed on the source register buses. -/
def DivuRetiresQuotient (row : DivRow) : Prop :=
  row.isDivu = true →
    row.rdNext.word =
      architecturalValue row.rd
        (Arith.divideUnsigned row.rs1Previous.word row.rs2Previous.word)

/-- The same claim on a `DIV` row, against the signed truncating quotient. -/
def DivRetiresQuotient (row : DivRow) : Prop :=
  row.isDiv = true →
    row.rdNext.word =
      architecturalValue row.rd
        (Arith.divideSigned row.rs1Previous.word row.rs2Previous.word)

/-- Soundness of the unsigned conclusion, from the unweakened row predicate.
Every step is a lemma of the family capsule: the read-only residuals identify
the consumed words with the computed limbs, `divu_result_word` derives the
quotient from the product chain and the comparison scan, and
`div_destination_word` carries it to the destination bus. -/
theorem divu_conclusion_sound (row : DivRow) (holds : DivHolds row) :
    DivuRetiresQuotient row := by
  intro selector
  obtain ⟨unsigned, division⟩ := div_flags_divu row holds selector
  have result : divResultBytes row = row.quotient := by
    simp [divResultBytes, division]
  rw [div_destination_word row holds, result,
    divu_result_word row holds unsigned, div_source_one_word row holds,
    div_source_two_word row holds]

/-- Soundness of the signed conclusion. -/
theorem div_conclusion_sound (row : DivRow) (holds : DivHolds row) :
    DivRetiresQuotient row := by
  intro selector
  obtain ⟨signed, division⟩ := div_flags_div row holds selector
  have result : divResultBytes row = row.quotient := by
    simp [divResultBytes, division]
  rw [div_destination_word row holds, result,
    div_result_word row holds signed, div_source_one_word row holds,
    div_source_two_word row holds]


/-! ## Control 1 — deleted zero-divisor convention

Issue #137: *delete `zero_divisor * (q_l - 255) = 0`; exhibit a divide-by-zero
row whose quotient is not all ones.*

On the zero-divisor branch every divisor limb is zero, so the eight product
residuals degenerate to `remainder = dividend` and say nothing at all about the
quotient. The four `zero_divisor * (q[limb] - 255) = 0` residuals are the only
thing that commits the ISA's `DIVU x, 0 = 2 ^ 32 - 1` convention. Delete the
limb-0 member and the low byte of the quotient is free.

Certifies the branch shared by `DIV`, `DIVU`, `REM` and `REMU`: the same four
residuals carry the all-ones convention for both signed and unsigned division,
and the row below exhibits it on the `DIVU` selector.
-/

structure DivHoldsWithoutZeroDivisorQuotient0 (row : DivRow) : Prop where
  /-- The placement residual `active - is_active` together with the four
  selector booleanity residuals: exactly one selector is set. -/
  selectorUnique :
    row.isDiv.toNat + row.isDivu.toNat + row.isRem.toNat + row.isRemu.toNat = 1
  /-- Booleanity of `special_case = zero_divisor + r_zero`. -/
  specialExclusive : row.zeroDivisor = true → row.rZero = false
  /-- `zero_divisor * rs2_next[limb] = 0`. -/
  zeroDivisorLimb0 : row.zeroDivisor = true → row.rs2Next.limb0 = 0
  zeroDivisorLimb1 : row.zeroDivisor = true → row.rs2Next.limb1 = 0
  zeroDivisorLimb2 : row.zeroDivisor = true → row.rs2Next.limb2 = 0
  zeroDivisorLimb3 : row.zeroDivisor = true → row.rs2Next.limb3 = 0
  -- `zeroDivisorQuotient0` is deliberately absent: this is the mutation.
  /-- `zero_divisor * (q[limb] - 255) = 0`: the all-ones quotient. -/
  zeroDivisorQuotient1 : row.zeroDivisor = true → row.quotient.limb1 = 255
  zeroDivisorQuotient2 : row.zeroDivisor = true → row.quotient.limb2 = 255
  zeroDivisorQuotient3 : row.zeroDivisor = true → row.quotient.limb3 = 255
  /-- `c_sum_inv` witnesses a nonzero divisor limb sum off the zero-divisor
  branch. -/
  divisorNonzero : row.zeroDivisor = false → row.rs2Next.value ≠ 0
  /-- `r_zero * r[limb] = 0`. -/
  remainderZeroLimb0 : row.rZero = true → row.remainder.limb0 = 0
  remainderZeroLimb1 : row.rZero = true → row.remainder.limb1 = 0
  remainderZeroLimb2 : row.rZero = true → row.remainder.limb2 = 0
  remainderZeroLimb3 : row.rZero = true → row.remainder.limb3 = 0
  /-- `r_sum_inv` witnesses a nonzero remainder off both special branches. -/
  remainderNonzero :
    row.zeroDivisor = false → row.rZero = false → row.remainder.value ≠ 0
  /-- `(1 - is_signed) * b_sign = 0` and `(1 - is_signed) * c_sign = 0`. -/
  unsignedDividendSign : row.isSigned = false → row.bSign = false
  unsignedDivisorSign : row.isSigned = false → row.cSign = false
  /-- `sign_xor = b_sign + c_sign - 2 * b_sign * c_sign`. -/
  signXorDefinition : row.signXor = (row.bSign != row.cSign)
  /-- `(1 - zero_divisor) * q_sum * (q_sign - sign_xor) = 0`. -/
  quotientSignMatches :
    row.zeroDivisor = false → row.quotient.value ≠ 0 → row.qSign = row.signXor
  /-- `(1 - zero_divisor) * (q_sign - sign_xor) * q_sign = 0`. -/
  quotientSignImpliesXor :
    row.zeroDivisor = false → row.qSign = true → row.signXor = true
  /-- `zero_divisor * (q_sign - is_signed) = 0`. -/
  zeroDivisorQuotientSign :
    row.zeroDivisor = true → row.qSign = row.isSigned
  /-- `(1 - sign_xor) * (r_abs[limb] - r[limb]) = 0`. -/
  absSameLimb0 : row.signXor = false → row.remainderAbs.limb0 = row.remainder.limb0
  absSameLimb1 : row.signXor = false → row.remainderAbs.limb1 = row.remainder.limb1
  absSameLimb2 : row.signXor = false → row.remainderAbs.limb2 = row.remainder.limb2
  absSameLimb3 : row.signXor = false → row.remainderAbs.limb3 = row.remainder.limb3
  /-- The two's complement negation chain used when `sign_xor = 1`. The three
  residuals per limb pin each carry to a bit, force a zero carry to zero the
  absolute limb, and (through `r_inv`) exclude the value `256`. -/
  negationRecurrence :
    row.signXor = true →
      ∃ n0 n1 n2 n3 : Bool,
        row.remainder.limb0.toNat + row.remainderAbs.limb0.toNat =
            256 * n0.toNat ∧
        n0.toNat + row.remainder.limb1.toNat + row.remainderAbs.limb1.toNat =
            256 * n1.toNat ∧
        n1.toNat + row.remainder.limb2.toNat + row.remainderAbs.limb2.toNat =
            256 * n2.toNat ∧
        n2.toNat + row.remainder.limb3.toNat + row.remainderAbs.limb3.toNat =
            256 * n3.toNat ∧
        (n0 = false → row.remainderAbs.limb0 = 0) ∧
        (n1 = false → row.remainderAbs.limb1 = 0) ∧
        (n2 = false → row.remainderAbs.limb2 = 0) ∧
        (n3 = false → row.remainderAbs.limb3 = 0) ∧
        (n1 = n0 ∨ n1 = true) ∧
        (n2 = n1 ∨ n2 = true) ∧
        (n3 = n2 ∨ n3 = true)
  /-- The eight `product_carries` residuals with their `range_check_8_11`
  carry components. This is the AIR's proof that
  `divisor * quotient + remainder = dividend` over sign-extended limbs. -/
  productRecurrence :
    ∃ k0 k1 k2 k3 k4 k5 k6 k7 : Nat,
      k0 < 2048 ∧ k1 < 2048 ∧ k2 < 2048 ∧ k3 < 2048 ∧
      k4 < 2048 ∧ k5 < 2048 ∧ k6 < 2048 ∧ k7 < 2048 ∧
      divConv0 row = row.rs1Next.limb0.toNat + 256 * k0 ∧
      k0 + divConv1 row = row.rs1Next.limb1.toNat + 256 * k1 ∧
      k1 + divConv2 row = row.rs1Next.limb2.toNat + 256 * k2 ∧
      k2 + divConv3 row = row.rs1Next.limb3.toNat + 256 * k3 ∧
      k3 + divConv4 row = divDividendHigh row + 256 * k4 ∧
      k4 + divConv5 row = divDividendHigh row + 256 * k5 ∧
      k5 + divConv6 row = divDividendHigh row + 256 * k6 ∧
      k6 + divConv7 row = divDividendHigh row + 256 * k7
  /-- `sign_range`: `2 * is_signed * (rs1_next[3] - 128 * b_sign)` is a byte,
  which pins `b_sign` to the dividend's top bit on signed rows. -/
  dividendSignBit :
    row.isSigned = true →
      row.bSign = decide (128 ≤ row.rs1Next.limb3.toNat)
  /-- `sign_range`, second component: `c_sign` is the divisor's top bit. -/
  divisorSignBit :
    row.isSigned = true →
      row.cSign = decide (128 ≤ row.rs2Next.limb3.toNat)
  /-- `quotient_sign_range`: on a signed row with a nonzero divisor that is not
  the both-negative class, `q[3] - 128 * q_sign` fits in seven bits, pinning
  `q_sign` to the quotient's top bit. -/
  quotientSignBit :
    row.isSigned = true →
      row.zeroDivisor = false →
      ¬(row.bSign = true ∧ row.cSign = true) →
      row.qSign = decide (128 ≤ row.quotient.limb3.toNat)
  /-- `active * (1 - prefixes[0]) = 0` with all markers and `special_case`
  boolean: exactly one of the five scan participants is set. -/
  scanTotal :
    row.zeroDivisor.toNat + row.rZero.toNat +
        row.ltMarker3.toNat + row.ltMarker2.toNat +
        row.ltMarker1.toNat + row.ltMarker0.toNat = 1
  /-- `(1 - prefixes[limb]) * diffs[limb] = 0`, high limb first. -/
  scanEqual3 :
    row.zeroDivisor = false → row.rZero = false → row.ltMarker3 = false →
      divCompareDiff3 row = 0
  scanEqual2 :
    row.zeroDivisor = false → row.rZero = false → row.ltMarker3 = false →
      row.ltMarker2 = false → divCompareDiff2 row = 0
  scanEqual1 :
    row.zeroDivisor = false → row.rZero = false → row.ltMarker3 = false →
      row.ltMarker2 = false → row.ltMarker1 = false → divCompareDiff1 row = 0
  scanEqual0 :
    row.zeroDivisor = false → row.rZero = false → row.ltMarker3 = false →
      row.ltMarker2 = false → row.ltMarker1 = false → row.ltMarker0 = false →
      divCompareDiff0 row = 0
  /-- `lt_markers[limb] * (lt_diff - diffs[limb]) = 0`. -/
  scanMarker3 : row.ltMarker3 = true → (row.ltDiff : Int) = divCompareDiff3 row
  scanMarker2 : row.ltMarker2 = true → (row.ltDiff : Int) = divCompareDiff2 row
  scanMarker1 : row.ltMarker1 = true → (row.ltDiff : Int) = divCompareDiff1 row
  scanMarker0 : row.ltMarker0 = true → (row.ltDiff : Int) = divCompareDiff0 row
  /-- `positive_remainder_diff`: `lt_diff - 1` is a `range_check_20` value off
  the special branches. -/
  ltDiffLower : row.zeroDivisor = false → row.rZero = false → 1 ≤ row.ltDiff
  ltDiffUpper :
    row.zeroDivisor = false → row.rZero = false → row.ltDiff ≤ 1048576
  /-- `destinationConstraints`: the write-enable witness is exact. -/
  destinationFlag : row.destinationNonzero = decide (row.rd ≠ zeroRegister)
  /-- `destinationResultConstraints`. -/
  destinationLimb0 :
    row.rdNext.limb0 =
      if row.destinationNonzero then (divResultBytes row).limb0 else 0
  destinationLimb1 :
    row.rdNext.limb1 =
      if row.destinationNonzero then (divResultBytes row).limb1 else 0
  destinationLimb2 :
    row.rdNext.limb2 =
      if row.destinationNonzero then (divResultBytes row).limb2 else 0
  destinationLimb3 :
    row.rdNext.limb3 =
      if row.destinationNonzero then (divResultBytes row).limb3 else 0
  /-- `readOnlyAccessConstraints` for both source registers. -/
  sourceOneLimb0 : row.rs1Next.limb0 = row.rs1Previous.limb0
  sourceOneLimb1 : row.rs1Next.limb1 = row.rs1Previous.limb1
  sourceOneLimb2 : row.rs1Next.limb2 = row.rs1Previous.limb2
  sourceOneLimb3 : row.rs1Next.limb3 = row.rs1Previous.limb3
  sourceTwoLimb0 : row.rs2Next.limb0 = row.rs2Previous.limb0
  sourceTwoLimb1 : row.rs2Next.limb1 = row.rs2Previous.limb1
  sourceTwoLimb2 : row.rs2Next.limb2 = row.rs2Previous.limb2
  sourceTwoLimb3 : row.rs2Next.limb3 = row.rs2Previous.limb3
  /-- The access-chain clock gaps, `range_check_20` on `next - previous - 1`. -/
  clockPositive : 0 < row.clock
  sourceOneClock :
    validPreviousClock row.rs1PreviousClock (accessClock row.clock 1)
  sourceTwoClock :
    validPreviousClock row.rs2PreviousClock (accessClock row.clock 2)
  destinationClock :
    validPreviousClock row.rdPreviousClock (accessClock row.clock 3)
  /-- The emitted `registers_state` program counter. -/
  nextPcResult : row.claimedNextPc = nextPc row.pc

/-- Deleting the constraint really is a deletion: every honest row still
satisfies the weakened predicate, so the control below is not a statement
about a predicate nothing satisfies. -/
theorem divHolds_weakens_zeroDivisorQuotient0
    (row : DivRow)
    (holds : DivHolds row) :
    DivHoldsWithoutZeroDivisorQuotient0 row where
  selectorUnique := holds.selectorUnique
  specialExclusive := holds.specialExclusive
  zeroDivisorLimb0 := holds.zeroDivisorLimb0
  zeroDivisorLimb1 := holds.zeroDivisorLimb1
  zeroDivisorLimb2 := holds.zeroDivisorLimb2
  zeroDivisorLimb3 := holds.zeroDivisorLimb3
  zeroDivisorQuotient1 := holds.zeroDivisorQuotient1
  zeroDivisorQuotient2 := holds.zeroDivisorQuotient2
  zeroDivisorQuotient3 := holds.zeroDivisorQuotient3
  divisorNonzero := holds.divisorNonzero
  remainderZeroLimb0 := holds.remainderZeroLimb0
  remainderZeroLimb1 := holds.remainderZeroLimb1
  remainderZeroLimb2 := holds.remainderZeroLimb2
  remainderZeroLimb3 := holds.remainderZeroLimb3
  remainderNonzero := holds.remainderNonzero
  unsignedDividendSign := holds.unsignedDividendSign
  unsignedDivisorSign := holds.unsignedDivisorSign
  signXorDefinition := holds.signXorDefinition
  quotientSignMatches := holds.quotientSignMatches
  quotientSignImpliesXor := holds.quotientSignImpliesXor
  zeroDivisorQuotientSign := holds.zeroDivisorQuotientSign
  absSameLimb0 := holds.absSameLimb0
  absSameLimb1 := holds.absSameLimb1
  absSameLimb2 := holds.absSameLimb2
  absSameLimb3 := holds.absSameLimb3
  negationRecurrence := holds.negationRecurrence
  productRecurrence := holds.productRecurrence
  dividendSignBit := holds.dividendSignBit
  divisorSignBit := holds.divisorSignBit
  quotientSignBit := holds.quotientSignBit
  scanTotal := holds.scanTotal
  scanEqual3 := holds.scanEqual3
  scanEqual2 := holds.scanEqual2
  scanEqual1 := holds.scanEqual1
  scanEqual0 := holds.scanEqual0
  scanMarker3 := holds.scanMarker3
  scanMarker2 := holds.scanMarker2
  scanMarker1 := holds.scanMarker1
  scanMarker0 := holds.scanMarker0
  ltDiffLower := holds.ltDiffLower
  ltDiffUpper := holds.ltDiffUpper
  destinationFlag := holds.destinationFlag
  destinationLimb0 := holds.destinationLimb0
  destinationLimb1 := holds.destinationLimb1
  destinationLimb2 := holds.destinationLimb2
  destinationLimb3 := holds.destinationLimb3
  sourceOneLimb0 := holds.sourceOneLimb0
  sourceOneLimb1 := holds.sourceOneLimb1
  sourceOneLimb2 := holds.sourceOneLimb2
  sourceOneLimb3 := holds.sourceOneLimb3
  sourceTwoLimb0 := holds.sourceTwoLimb0
  sourceTwoLimb1 := holds.sourceTwoLimb1
  sourceTwoLimb2 := holds.sourceTwoLimb2
  sourceTwoLimb3 := holds.sourceTwoLimb3
  clockPositive := holds.clockPositive
  sourceOneClock := holds.sourceOneClock
  sourceTwoClock := holds.sourceTwoClock
  destinationClock := holds.destinationClock
  nextPcResult := holds.nextPcResult

/-- `DIVU x3, x1, x2` dividing `7` by zero. Every surviving residual holds --
the divisor limbs are zero, the remainder is the dividend, the three other
convention residuals still pin limbs 1 to 3 to `255` -- but the freed limb 0
commits `0xffffff00` instead of the architectural all-ones quotient. -/
def divFreeZeroQuotientRow : DivRow :=
  divWitnessRow false true false false 3 1 2
    (divBytes 7 0 0 0) (divBytes 0 0 0 0) (divBytes 0 255 255 255)
    (divBytes 7 0 0 0) (divBytes 7 0 0 0) (divBytes 0 255 255 255)
    true false false false false false
    false false false false 0 true

theorem divFreeZeroQuotientRow_satisfies :
    DivHoldsWithoutZeroDivisorQuotient0 divFreeZeroQuotientRow := by
  div_witness_holds ⟨0, 0, 0, 0, 0, 0, 0, 0, by decide⟩
    negating ⟨false, false, false, false, by decide⟩

theorem divFreeZeroQuotientRow_refutes :
    ¬ DivuRetiresQuotient divFreeZeroQuotientRow := by
  intro claim
  exact absurd (claim (by decide)) (by decide)

/-- The published control. -/
def divFreeZeroDivisorQuotient :
    MutationControl DivHoldsWithoutZeroDivisorQuotient0
      DivuRetiresQuotient where
  name := "div-zero-divisor-convention"
  witness := divFreeZeroQuotientRow
  satisfies := divFreeZeroQuotientRow_satisfies
  refutes := divFreeZeroQuotientRow_refutes

/-- The deletion is not free: no strengthening of the weakened predicate back
to `DivHolds` exists, because `DivHolds` implies the architectural claim and
the witness does not satisfy it. -/
theorem div_zero_divisor_convention_is_load_bearing :
    ¬ (∀ row, DivHoldsWithoutZeroDivisorQuotient0 row → DivHolds row) :=
  divFreeZeroDivisorQuotient.strictly_weaker DivHolds divu_conclusion_sound

/-! ## Control 2 — released comparison witness

Issue #137: *delete `active * (1 - prefixes_0) = 0`; exhibit a row whose
remainder is NOT smaller than the divisor.* This is the deletion that matters
most, because the product residuals alone leave the quotient underdetermined:
`divisor * quotient + remainder = dividend` has one solution per admissible
remainder, and only `|remainder| < |divisor|` selects the architectural one.

`scanTotal` is that residual. It forces exactly one of the five scan
participants -- `zero_divisor`, `r_zero` and the four `lt_markers` -- to be set,
which is what makes the high-to-low scan *find* a strictly positive difference
rather than merely permit one. With it deleted the whole marker vector may be
zero; the remaining `(1 - prefixes[limb]) * diffs[limb] = 0` residuals then
force every difference to vanish, i.e. `|remainder| = |divisor|` exactly, and
the row below divides `6` by `3` and retires `1`.

Certifies `DIV`, `DIVU`, `REM` and `REMU`: `scanTotal` is selector-independent
and every one of the four opcodes reaches its result through the same scan.
-/

structure DivHoldsWithoutScanTotal (row : DivRow) : Prop where
  /-- The placement residual `active - is_active` together with the four
  selector booleanity residuals: exactly one selector is set. -/
  selectorUnique :
    row.isDiv.toNat + row.isDivu.toNat + row.isRem.toNat + row.isRemu.toNat = 1
  /-- Booleanity of `special_case = zero_divisor + r_zero`. -/
  specialExclusive : row.zeroDivisor = true → row.rZero = false
  /-- `zero_divisor * rs2_next[limb] = 0`. -/
  zeroDivisorLimb0 : row.zeroDivisor = true → row.rs2Next.limb0 = 0
  zeroDivisorLimb1 : row.zeroDivisor = true → row.rs2Next.limb1 = 0
  zeroDivisorLimb2 : row.zeroDivisor = true → row.rs2Next.limb2 = 0
  zeroDivisorLimb3 : row.zeroDivisor = true → row.rs2Next.limb3 = 0
  /-- `zero_divisor * (q[limb] - 255) = 0`: the all-ones quotient. -/
  zeroDivisorQuotient0 : row.zeroDivisor = true → row.quotient.limb0 = 255
  zeroDivisorQuotient1 : row.zeroDivisor = true → row.quotient.limb1 = 255
  zeroDivisorQuotient2 : row.zeroDivisor = true → row.quotient.limb2 = 255
  zeroDivisorQuotient3 : row.zeroDivisor = true → row.quotient.limb3 = 255
  /-- `c_sum_inv` witnesses a nonzero divisor limb sum off the zero-divisor
  branch. -/
  divisorNonzero : row.zeroDivisor = false → row.rs2Next.value ≠ 0
  /-- `r_zero * r[limb] = 0`. -/
  remainderZeroLimb0 : row.rZero = true → row.remainder.limb0 = 0
  remainderZeroLimb1 : row.rZero = true → row.remainder.limb1 = 0
  remainderZeroLimb2 : row.rZero = true → row.remainder.limb2 = 0
  remainderZeroLimb3 : row.rZero = true → row.remainder.limb3 = 0
  /-- `r_sum_inv` witnesses a nonzero remainder off both special branches. -/
  remainderNonzero :
    row.zeroDivisor = false → row.rZero = false → row.remainder.value ≠ 0
  /-- `(1 - is_signed) * b_sign = 0` and `(1 - is_signed) * c_sign = 0`. -/
  unsignedDividendSign : row.isSigned = false → row.bSign = false
  unsignedDivisorSign : row.isSigned = false → row.cSign = false
  /-- `sign_xor = b_sign + c_sign - 2 * b_sign * c_sign`. -/
  signXorDefinition : row.signXor = (row.bSign != row.cSign)
  /-- `(1 - zero_divisor) * q_sum * (q_sign - sign_xor) = 0`. -/
  quotientSignMatches :
    row.zeroDivisor = false → row.quotient.value ≠ 0 → row.qSign = row.signXor
  /-- `(1 - zero_divisor) * (q_sign - sign_xor) * q_sign = 0`. -/
  quotientSignImpliesXor :
    row.zeroDivisor = false → row.qSign = true → row.signXor = true
  /-- `zero_divisor * (q_sign - is_signed) = 0`. -/
  zeroDivisorQuotientSign :
    row.zeroDivisor = true → row.qSign = row.isSigned
  /-- `(1 - sign_xor) * (r_abs[limb] - r[limb]) = 0`. -/
  absSameLimb0 : row.signXor = false → row.remainderAbs.limb0 = row.remainder.limb0
  absSameLimb1 : row.signXor = false → row.remainderAbs.limb1 = row.remainder.limb1
  absSameLimb2 : row.signXor = false → row.remainderAbs.limb2 = row.remainder.limb2
  absSameLimb3 : row.signXor = false → row.remainderAbs.limb3 = row.remainder.limb3
  /-- The two's complement negation chain used when `sign_xor = 1`. The three
  residuals per limb pin each carry to a bit, force a zero carry to zero the
  absolute limb, and (through `r_inv`) exclude the value `256`. -/
  negationRecurrence :
    row.signXor = true →
      ∃ n0 n1 n2 n3 : Bool,
        row.remainder.limb0.toNat + row.remainderAbs.limb0.toNat =
            256 * n0.toNat ∧
        n0.toNat + row.remainder.limb1.toNat + row.remainderAbs.limb1.toNat =
            256 * n1.toNat ∧
        n1.toNat + row.remainder.limb2.toNat + row.remainderAbs.limb2.toNat =
            256 * n2.toNat ∧
        n2.toNat + row.remainder.limb3.toNat + row.remainderAbs.limb3.toNat =
            256 * n3.toNat ∧
        (n0 = false → row.remainderAbs.limb0 = 0) ∧
        (n1 = false → row.remainderAbs.limb1 = 0) ∧
        (n2 = false → row.remainderAbs.limb2 = 0) ∧
        (n3 = false → row.remainderAbs.limb3 = 0) ∧
        (n1 = n0 ∨ n1 = true) ∧
        (n2 = n1 ∨ n2 = true) ∧
        (n3 = n2 ∨ n3 = true)
  /-- The eight `product_carries` residuals with their `range_check_8_11`
  carry components. This is the AIR's proof that
  `divisor * quotient + remainder = dividend` over sign-extended limbs. -/
  productRecurrence :
    ∃ k0 k1 k2 k3 k4 k5 k6 k7 : Nat,
      k0 < 2048 ∧ k1 < 2048 ∧ k2 < 2048 ∧ k3 < 2048 ∧
      k4 < 2048 ∧ k5 < 2048 ∧ k6 < 2048 ∧ k7 < 2048 ∧
      divConv0 row = row.rs1Next.limb0.toNat + 256 * k0 ∧
      k0 + divConv1 row = row.rs1Next.limb1.toNat + 256 * k1 ∧
      k1 + divConv2 row = row.rs1Next.limb2.toNat + 256 * k2 ∧
      k2 + divConv3 row = row.rs1Next.limb3.toNat + 256 * k3 ∧
      k3 + divConv4 row = divDividendHigh row + 256 * k4 ∧
      k4 + divConv5 row = divDividendHigh row + 256 * k5 ∧
      k5 + divConv6 row = divDividendHigh row + 256 * k6 ∧
      k6 + divConv7 row = divDividendHigh row + 256 * k7
  /-- `sign_range`: `2 * is_signed * (rs1_next[3] - 128 * b_sign)` is a byte,
  which pins `b_sign` to the dividend's top bit on signed rows. -/
  dividendSignBit :
    row.isSigned = true →
      row.bSign = decide (128 ≤ row.rs1Next.limb3.toNat)
  /-- `sign_range`, second component: `c_sign` is the divisor's top bit. -/
  divisorSignBit :
    row.isSigned = true →
      row.cSign = decide (128 ≤ row.rs2Next.limb3.toNat)
  /-- `quotient_sign_range`: on a signed row with a nonzero divisor that is not
  the both-negative class, `q[3] - 128 * q_sign` fits in seven bits, pinning
  `q_sign` to the quotient's top bit. -/
  quotientSignBit :
    row.isSigned = true →
      row.zeroDivisor = false →
      ¬(row.bSign = true ∧ row.cSign = true) →
      row.qSign = decide (128 ≤ row.quotient.limb3.toNat)
  -- `scanTotal` is deliberately absent: this is the mutation.
  -- `active * (1 - prefixes[0]) = 0` with all markers and `special_case`
  /-- `(1 - prefixes[limb]) * diffs[limb] = 0`, high limb first. -/
  scanEqual3 :
    row.zeroDivisor = false → row.rZero = false → row.ltMarker3 = false →
      divCompareDiff3 row = 0
  scanEqual2 :
    row.zeroDivisor = false → row.rZero = false → row.ltMarker3 = false →
      row.ltMarker2 = false → divCompareDiff2 row = 0
  scanEqual1 :
    row.zeroDivisor = false → row.rZero = false → row.ltMarker3 = false →
      row.ltMarker2 = false → row.ltMarker1 = false → divCompareDiff1 row = 0
  scanEqual0 :
    row.zeroDivisor = false → row.rZero = false → row.ltMarker3 = false →
      row.ltMarker2 = false → row.ltMarker1 = false → row.ltMarker0 = false →
      divCompareDiff0 row = 0
  /-- `lt_markers[limb] * (lt_diff - diffs[limb]) = 0`. -/
  scanMarker3 : row.ltMarker3 = true → (row.ltDiff : Int) = divCompareDiff3 row
  scanMarker2 : row.ltMarker2 = true → (row.ltDiff : Int) = divCompareDiff2 row
  scanMarker1 : row.ltMarker1 = true → (row.ltDiff : Int) = divCompareDiff1 row
  scanMarker0 : row.ltMarker0 = true → (row.ltDiff : Int) = divCompareDiff0 row
  /-- `positive_remainder_diff`: `lt_diff - 1` is a `range_check_20` value off
  the special branches. -/
  ltDiffLower : row.zeroDivisor = false → row.rZero = false → 1 ≤ row.ltDiff
  ltDiffUpper :
    row.zeroDivisor = false → row.rZero = false → row.ltDiff ≤ 1048576
  /-- `destinationConstraints`: the write-enable witness is exact. -/
  destinationFlag : row.destinationNonzero = decide (row.rd ≠ zeroRegister)
  /-- `destinationResultConstraints`. -/
  destinationLimb0 :
    row.rdNext.limb0 =
      if row.destinationNonzero then (divResultBytes row).limb0 else 0
  destinationLimb1 :
    row.rdNext.limb1 =
      if row.destinationNonzero then (divResultBytes row).limb1 else 0
  destinationLimb2 :
    row.rdNext.limb2 =
      if row.destinationNonzero then (divResultBytes row).limb2 else 0
  destinationLimb3 :
    row.rdNext.limb3 =
      if row.destinationNonzero then (divResultBytes row).limb3 else 0
  /-- `readOnlyAccessConstraints` for both source registers. -/
  sourceOneLimb0 : row.rs1Next.limb0 = row.rs1Previous.limb0
  sourceOneLimb1 : row.rs1Next.limb1 = row.rs1Previous.limb1
  sourceOneLimb2 : row.rs1Next.limb2 = row.rs1Previous.limb2
  sourceOneLimb3 : row.rs1Next.limb3 = row.rs1Previous.limb3
  sourceTwoLimb0 : row.rs2Next.limb0 = row.rs2Previous.limb0
  sourceTwoLimb1 : row.rs2Next.limb1 = row.rs2Previous.limb1
  sourceTwoLimb2 : row.rs2Next.limb2 = row.rs2Previous.limb2
  sourceTwoLimb3 : row.rs2Next.limb3 = row.rs2Previous.limb3
  /-- The access-chain clock gaps, `range_check_20` on `next - previous - 1`. -/
  clockPositive : 0 < row.clock
  sourceOneClock :
    validPreviousClock row.rs1PreviousClock (accessClock row.clock 1)
  sourceTwoClock :
    validPreviousClock row.rs2PreviousClock (accessClock row.clock 2)
  destinationClock :
    validPreviousClock row.rdPreviousClock (accessClock row.clock 3)
  /-- The emitted `registers_state` program counter. -/
  nextPcResult : row.claimedNextPc = nextPc row.pc

/-- Deleting the constraint really is a deletion: every honest row still
satisfies the weakened predicate, so the control below is not a statement
about a predicate nothing satisfies. -/
theorem divHolds_weakens_scanTotal
    (row : DivRow)
    (holds : DivHolds row) :
    DivHoldsWithoutScanTotal row where
  selectorUnique := holds.selectorUnique
  specialExclusive := holds.specialExclusive
  zeroDivisorLimb0 := holds.zeroDivisorLimb0
  zeroDivisorLimb1 := holds.zeroDivisorLimb1
  zeroDivisorLimb2 := holds.zeroDivisorLimb2
  zeroDivisorLimb3 := holds.zeroDivisorLimb3
  zeroDivisorQuotient0 := holds.zeroDivisorQuotient0
  zeroDivisorQuotient1 := holds.zeroDivisorQuotient1
  zeroDivisorQuotient2 := holds.zeroDivisorQuotient2
  zeroDivisorQuotient3 := holds.zeroDivisorQuotient3
  divisorNonzero := holds.divisorNonzero
  remainderZeroLimb0 := holds.remainderZeroLimb0
  remainderZeroLimb1 := holds.remainderZeroLimb1
  remainderZeroLimb2 := holds.remainderZeroLimb2
  remainderZeroLimb3 := holds.remainderZeroLimb3
  remainderNonzero := holds.remainderNonzero
  unsignedDividendSign := holds.unsignedDividendSign
  unsignedDivisorSign := holds.unsignedDivisorSign
  signXorDefinition := holds.signXorDefinition
  quotientSignMatches := holds.quotientSignMatches
  quotientSignImpliesXor := holds.quotientSignImpliesXor
  zeroDivisorQuotientSign := holds.zeroDivisorQuotientSign
  absSameLimb0 := holds.absSameLimb0
  absSameLimb1 := holds.absSameLimb1
  absSameLimb2 := holds.absSameLimb2
  absSameLimb3 := holds.absSameLimb3
  negationRecurrence := holds.negationRecurrence
  productRecurrence := holds.productRecurrence
  dividendSignBit := holds.dividendSignBit
  divisorSignBit := holds.divisorSignBit
  quotientSignBit := holds.quotientSignBit
  scanEqual3 := holds.scanEqual3
  scanEqual2 := holds.scanEqual2
  scanEqual1 := holds.scanEqual1
  scanEqual0 := holds.scanEqual0
  scanMarker3 := holds.scanMarker3
  scanMarker2 := holds.scanMarker2
  scanMarker1 := holds.scanMarker1
  scanMarker0 := holds.scanMarker0
  ltDiffLower := holds.ltDiffLower
  ltDiffUpper := holds.ltDiffUpper
  destinationFlag := holds.destinationFlag
  destinationLimb0 := holds.destinationLimb0
  destinationLimb1 := holds.destinationLimb1
  destinationLimb2 := holds.destinationLimb2
  destinationLimb3 := holds.destinationLimb3
  sourceOneLimb0 := holds.sourceOneLimb0
  sourceOneLimb1 := holds.sourceOneLimb1
  sourceOneLimb2 := holds.sourceOneLimb2
  sourceOneLimb3 := holds.sourceOneLimb3
  sourceTwoLimb0 := holds.sourceTwoLimb0
  sourceTwoLimb1 := holds.sourceTwoLimb1
  sourceTwoLimb2 := holds.sourceTwoLimb2
  sourceTwoLimb3 := holds.sourceTwoLimb3
  clockPositive := holds.clockPositive
  sourceOneClock := holds.sourceOneClock
  sourceTwoClock := holds.sourceTwoClock
  destinationClock := holds.destinationClock
  nextPcResult := holds.nextPcResult

/-- `DIVU x3, x1, x2` computing `6 / 3`, committing quotient `1` and remainder
`3`. With the scan total released no marker need be set, so the four equality
residuals fire on every limb and are satisfied by `r_abs = divisor` -- a
remainder exactly as large as the divisor. `lt_diff` is parked at `1`, inside
its `range_check_20` window, and no `lt_markers[limb] * (lt_diff - diffs[limb])`
residual is active to contradict it. -/
def divSlackScanRow : DivRow :=
  divWitnessRow false true false false 3 1 2
    (divBytes 6 0 0 0) (divBytes 3 0 0 0) (divBytes 1 0 0 0)
    (divBytes 3 0 0 0) (divBytes 3 0 0 0) (divBytes 1 0 0 0)
    false false false false false false
    false false false false 1 true

theorem divSlackScanRow_satisfies :
    DivHoldsWithoutScanTotal divSlackScanRow := by
  div_witness_holds ⟨0, 0, 0, 0, 0, 0, 0, 0, by decide⟩
    negating ⟨false, false, false, false, by decide⟩

theorem divSlackScanRow_refutes :
    ¬ DivuRetiresQuotient divSlackScanRow := by
  intro claim
  exact absurd (claim (by decide)) (by decide)

/-- The published control. -/
def divReleasedComparison :
    MutationControl DivHoldsWithoutScanTotal
      DivuRetiresQuotient where
  name := "div-released-comparison-witness"
  witness := divSlackScanRow
  satisfies := divSlackScanRow_satisfies
  refutes := divSlackScanRow_refutes

/-- The deletion is not free: no strengthening of the weakened predicate back
to `DivHolds` exists, because `DivHolds` implies the architectural claim and
the witness does not satisfy it. -/
theorem div_scan_total_is_load_bearing :
    ¬ (∀ row, DivHoldsWithoutScanTotal row → DivHolds row) :=
  divReleasedComparison.strictly_weaker DivHolds divu_conclusion_sound

/-! ## Control 3 — wrong remainder magnitude

Issue #137: *delete the absolute-remainder negation constraint; exhibit a
signed row whose remainder is wrong.*

`negationRecurrence` is the two's complement chain that makes `r_abs` the
magnitude of `r` when `sign_xor = 1`. It is the only link between the committed
remainder and the value the comparison scan actually compares against the
divisor. Delete it and `r_abs` becomes an unconstrained decoration: the prover
picks a small `r_abs` to satisfy the scan while committing a remainder whose
magnitude exceeds the divisor, and the product chain then admits a quotient one
short of the architectural one.

Note that the *sign* of the remainder is not deletable in this transcription:
`r_hi = b_sign * (1 - r_zero) * 255` is a definition of the sign-extension byte
rather than a residual, so the remainder always carries the dividend's sign.
What the negation chain carries is the magnitude, and that is what this control
frees.

Certifies `DIV` and `REM`: the chain is gated on `sign_xor = 1`, which only the
two signed selectors can set.
-/

structure DivHoldsWithoutNegationRecurrence (row : DivRow) : Prop where
  /-- The placement residual `active - is_active` together with the four
  selector booleanity residuals: exactly one selector is set. -/
  selectorUnique :
    row.isDiv.toNat + row.isDivu.toNat + row.isRem.toNat + row.isRemu.toNat = 1
  /-- Booleanity of `special_case = zero_divisor + r_zero`. -/
  specialExclusive : row.zeroDivisor = true → row.rZero = false
  /-- `zero_divisor * rs2_next[limb] = 0`. -/
  zeroDivisorLimb0 : row.zeroDivisor = true → row.rs2Next.limb0 = 0
  zeroDivisorLimb1 : row.zeroDivisor = true → row.rs2Next.limb1 = 0
  zeroDivisorLimb2 : row.zeroDivisor = true → row.rs2Next.limb2 = 0
  zeroDivisorLimb3 : row.zeroDivisor = true → row.rs2Next.limb3 = 0
  /-- `zero_divisor * (q[limb] - 255) = 0`: the all-ones quotient. -/
  zeroDivisorQuotient0 : row.zeroDivisor = true → row.quotient.limb0 = 255
  zeroDivisorQuotient1 : row.zeroDivisor = true → row.quotient.limb1 = 255
  zeroDivisorQuotient2 : row.zeroDivisor = true → row.quotient.limb2 = 255
  zeroDivisorQuotient3 : row.zeroDivisor = true → row.quotient.limb3 = 255
  /-- `c_sum_inv` witnesses a nonzero divisor limb sum off the zero-divisor
  branch. -/
  divisorNonzero : row.zeroDivisor = false → row.rs2Next.value ≠ 0
  /-- `r_zero * r[limb] = 0`. -/
  remainderZeroLimb0 : row.rZero = true → row.remainder.limb0 = 0
  remainderZeroLimb1 : row.rZero = true → row.remainder.limb1 = 0
  remainderZeroLimb2 : row.rZero = true → row.remainder.limb2 = 0
  remainderZeroLimb3 : row.rZero = true → row.remainder.limb3 = 0
  /-- `r_sum_inv` witnesses a nonzero remainder off both special branches. -/
  remainderNonzero :
    row.zeroDivisor = false → row.rZero = false → row.remainder.value ≠ 0
  /-- `(1 - is_signed) * b_sign = 0` and `(1 - is_signed) * c_sign = 0`. -/
  unsignedDividendSign : row.isSigned = false → row.bSign = false
  unsignedDivisorSign : row.isSigned = false → row.cSign = false
  /-- `sign_xor = b_sign + c_sign - 2 * b_sign * c_sign`. -/
  signXorDefinition : row.signXor = (row.bSign != row.cSign)
  /-- `(1 - zero_divisor) * q_sum * (q_sign - sign_xor) = 0`. -/
  quotientSignMatches :
    row.zeroDivisor = false → row.quotient.value ≠ 0 → row.qSign = row.signXor
  /-- `(1 - zero_divisor) * (q_sign - sign_xor) * q_sign = 0`. -/
  quotientSignImpliesXor :
    row.zeroDivisor = false → row.qSign = true → row.signXor = true
  /-- `zero_divisor * (q_sign - is_signed) = 0`. -/
  zeroDivisorQuotientSign :
    row.zeroDivisor = true → row.qSign = row.isSigned
  /-- `(1 - sign_xor) * (r_abs[limb] - r[limb]) = 0`. -/
  absSameLimb0 : row.signXor = false → row.remainderAbs.limb0 = row.remainder.limb0
  absSameLimb1 : row.signXor = false → row.remainderAbs.limb1 = row.remainder.limb1
  absSameLimb2 : row.signXor = false → row.remainderAbs.limb2 = row.remainder.limb2
  absSameLimb3 : row.signXor = false → row.remainderAbs.limb3 = row.remainder.limb3
  -- `negationRecurrence` is deliberately absent: this is the mutation.
  -- The two's complement negation chain used when `sign_xor = 1`. The three
  -- residuals per limb pin each carry to a bit, force a zero carry to zero the
  -- absolute limb, and (through `r_inv`) exclude the value `256`.
  /-- The eight `product_carries` residuals with their `range_check_8_11`
  carry components. This is the AIR's proof that
  `divisor * quotient + remainder = dividend` over sign-extended limbs. -/
  productRecurrence :
    ∃ k0 k1 k2 k3 k4 k5 k6 k7 : Nat,
      k0 < 2048 ∧ k1 < 2048 ∧ k2 < 2048 ∧ k3 < 2048 ∧
      k4 < 2048 ∧ k5 < 2048 ∧ k6 < 2048 ∧ k7 < 2048 ∧
      divConv0 row = row.rs1Next.limb0.toNat + 256 * k0 ∧
      k0 + divConv1 row = row.rs1Next.limb1.toNat + 256 * k1 ∧
      k1 + divConv2 row = row.rs1Next.limb2.toNat + 256 * k2 ∧
      k2 + divConv3 row = row.rs1Next.limb3.toNat + 256 * k3 ∧
      k3 + divConv4 row = divDividendHigh row + 256 * k4 ∧
      k4 + divConv5 row = divDividendHigh row + 256 * k5 ∧
      k5 + divConv6 row = divDividendHigh row + 256 * k6 ∧
      k6 + divConv7 row = divDividendHigh row + 256 * k7
  /-- `sign_range`: `2 * is_signed * (rs1_next[3] - 128 * b_sign)` is a byte,
  which pins `b_sign` to the dividend's top bit on signed rows. -/
  dividendSignBit :
    row.isSigned = true →
      row.bSign = decide (128 ≤ row.rs1Next.limb3.toNat)
  /-- `sign_range`, second component: `c_sign` is the divisor's top bit. -/
  divisorSignBit :
    row.isSigned = true →
      row.cSign = decide (128 ≤ row.rs2Next.limb3.toNat)
  /-- `quotient_sign_range`: on a signed row with a nonzero divisor that is not
  the both-negative class, `q[3] - 128 * q_sign` fits in seven bits, pinning
  `q_sign` to the quotient's top bit. -/
  quotientSignBit :
    row.isSigned = true →
      row.zeroDivisor = false →
      ¬(row.bSign = true ∧ row.cSign = true) →
      row.qSign = decide (128 ≤ row.quotient.limb3.toNat)
  /-- `active * (1 - prefixes[0]) = 0` with all markers and `special_case`
  boolean: exactly one of the five scan participants is set. -/
  scanTotal :
    row.zeroDivisor.toNat + row.rZero.toNat +
        row.ltMarker3.toNat + row.ltMarker2.toNat +
        row.ltMarker1.toNat + row.ltMarker0.toNat = 1
  /-- `(1 - prefixes[limb]) * diffs[limb] = 0`, high limb first. -/
  scanEqual3 :
    row.zeroDivisor = false → row.rZero = false → row.ltMarker3 = false →
      divCompareDiff3 row = 0
  scanEqual2 :
    row.zeroDivisor = false → row.rZero = false → row.ltMarker3 = false →
      row.ltMarker2 = false → divCompareDiff2 row = 0
  scanEqual1 :
    row.zeroDivisor = false → row.rZero = false → row.ltMarker3 = false →
      row.ltMarker2 = false → row.ltMarker1 = false → divCompareDiff1 row = 0
  scanEqual0 :
    row.zeroDivisor = false → row.rZero = false → row.ltMarker3 = false →
      row.ltMarker2 = false → row.ltMarker1 = false → row.ltMarker0 = false →
      divCompareDiff0 row = 0
  /-- `lt_markers[limb] * (lt_diff - diffs[limb]) = 0`. -/
  scanMarker3 : row.ltMarker3 = true → (row.ltDiff : Int) = divCompareDiff3 row
  scanMarker2 : row.ltMarker2 = true → (row.ltDiff : Int) = divCompareDiff2 row
  scanMarker1 : row.ltMarker1 = true → (row.ltDiff : Int) = divCompareDiff1 row
  scanMarker0 : row.ltMarker0 = true → (row.ltDiff : Int) = divCompareDiff0 row
  /-- `positive_remainder_diff`: `lt_diff - 1` is a `range_check_20` value off
  the special branches. -/
  ltDiffLower : row.zeroDivisor = false → row.rZero = false → 1 ≤ row.ltDiff
  ltDiffUpper :
    row.zeroDivisor = false → row.rZero = false → row.ltDiff ≤ 1048576
  /-- `destinationConstraints`: the write-enable witness is exact. -/
  destinationFlag : row.destinationNonzero = decide (row.rd ≠ zeroRegister)
  /-- `destinationResultConstraints`. -/
  destinationLimb0 :
    row.rdNext.limb0 =
      if row.destinationNonzero then (divResultBytes row).limb0 else 0
  destinationLimb1 :
    row.rdNext.limb1 =
      if row.destinationNonzero then (divResultBytes row).limb1 else 0
  destinationLimb2 :
    row.rdNext.limb2 =
      if row.destinationNonzero then (divResultBytes row).limb2 else 0
  destinationLimb3 :
    row.rdNext.limb3 =
      if row.destinationNonzero then (divResultBytes row).limb3 else 0
  /-- `readOnlyAccessConstraints` for both source registers. -/
  sourceOneLimb0 : row.rs1Next.limb0 = row.rs1Previous.limb0
  sourceOneLimb1 : row.rs1Next.limb1 = row.rs1Previous.limb1
  sourceOneLimb2 : row.rs1Next.limb2 = row.rs1Previous.limb2
  sourceOneLimb3 : row.rs1Next.limb3 = row.rs1Previous.limb3
  sourceTwoLimb0 : row.rs2Next.limb0 = row.rs2Previous.limb0
  sourceTwoLimb1 : row.rs2Next.limb1 = row.rs2Previous.limb1
  sourceTwoLimb2 : row.rs2Next.limb2 = row.rs2Previous.limb2
  sourceTwoLimb3 : row.rs2Next.limb3 = row.rs2Previous.limb3
  /-- The access-chain clock gaps, `range_check_20` on `next - previous - 1`. -/
  clockPositive : 0 < row.clock
  sourceOneClock :
    validPreviousClock row.rs1PreviousClock (accessClock row.clock 1)
  sourceTwoClock :
    validPreviousClock row.rs2PreviousClock (accessClock row.clock 2)
  destinationClock :
    validPreviousClock row.rdPreviousClock (accessClock row.clock 3)
  /-- The emitted `registers_state` program counter. -/
  nextPcResult : row.claimedNextPc = nextPc row.pc

/-- Deleting the constraint really is a deletion: every honest row still
satisfies the weakened predicate, so the control below is not a statement
about a predicate nothing satisfies. -/
theorem divHolds_weakens_negationRecurrence
    (row : DivRow)
    (holds : DivHolds row) :
    DivHoldsWithoutNegationRecurrence row where
  selectorUnique := holds.selectorUnique
  specialExclusive := holds.specialExclusive
  zeroDivisorLimb0 := holds.zeroDivisorLimb0
  zeroDivisorLimb1 := holds.zeroDivisorLimb1
  zeroDivisorLimb2 := holds.zeroDivisorLimb2
  zeroDivisorLimb3 := holds.zeroDivisorLimb3
  zeroDivisorQuotient0 := holds.zeroDivisorQuotient0
  zeroDivisorQuotient1 := holds.zeroDivisorQuotient1
  zeroDivisorQuotient2 := holds.zeroDivisorQuotient2
  zeroDivisorQuotient3 := holds.zeroDivisorQuotient3
  divisorNonzero := holds.divisorNonzero
  remainderZeroLimb0 := holds.remainderZeroLimb0
  remainderZeroLimb1 := holds.remainderZeroLimb1
  remainderZeroLimb2 := holds.remainderZeroLimb2
  remainderZeroLimb3 := holds.remainderZeroLimb3
  remainderNonzero := holds.remainderNonzero
  unsignedDividendSign := holds.unsignedDividendSign
  unsignedDivisorSign := holds.unsignedDivisorSign
  signXorDefinition := holds.signXorDefinition
  quotientSignMatches := holds.quotientSignMatches
  quotientSignImpliesXor := holds.quotientSignImpliesXor
  zeroDivisorQuotientSign := holds.zeroDivisorQuotientSign
  absSameLimb0 := holds.absSameLimb0
  absSameLimb1 := holds.absSameLimb1
  absSameLimb2 := holds.absSameLimb2
  absSameLimb3 := holds.absSameLimb3
  productRecurrence := holds.productRecurrence
  dividendSignBit := holds.dividendSignBit
  divisorSignBit := holds.divisorSignBit
  quotientSignBit := holds.quotientSignBit
  scanTotal := holds.scanTotal
  scanEqual3 := holds.scanEqual3
  scanEqual2 := holds.scanEqual2
  scanEqual1 := holds.scanEqual1
  scanEqual0 := holds.scanEqual0
  scanMarker3 := holds.scanMarker3
  scanMarker2 := holds.scanMarker2
  scanMarker1 := holds.scanMarker1
  scanMarker0 := holds.scanMarker0
  ltDiffLower := holds.ltDiffLower
  ltDiffUpper := holds.ltDiffUpper
  destinationFlag := holds.destinationFlag
  destinationLimb0 := holds.destinationLimb0
  destinationLimb1 := holds.destinationLimb1
  destinationLimb2 := holds.destinationLimb2
  destinationLimb3 := holds.destinationLimb3
  sourceOneLimb0 := holds.sourceOneLimb0
  sourceOneLimb1 := holds.sourceOneLimb1
  sourceOneLimb2 := holds.sourceOneLimb2
  sourceOneLimb3 := holds.sourceOneLimb3
  sourceTwoLimb0 := holds.sourceTwoLimb0
  sourceTwoLimb1 := holds.sourceTwoLimb1
  sourceTwoLimb2 := holds.sourceTwoLimb2
  sourceTwoLimb3 := holds.sourceTwoLimb3
  clockPositive := holds.clockPositive
  sourceOneClock := holds.sourceOneClock
  sourceTwoClock := holds.sourceTwoClock
  destinationClock := holds.destinationClock
  nextPcResult := holds.nextPcResult

/-- `DIV x3, x1, x2` computing `(-7) / 3`. The architectural answer is `-2`
remainder `-1`; this row commits quotient `-1` and remainder `-4`, which
satisfies the eight product residuals exactly (all eight carries are `3`) and
every sign lookup. Only the deleted negation chain would have caught it: the
row claims `r_abs = 1` for a remainder of `-4`, and that lie is what carries it
past the `|remainder| < |divisor|` scan. -/
def divFreeRemainderAbsRow : DivRow :=
  divWitnessRow true false false false 3 1 2
    (divBytes 249 255 255 255) (divBytes 3 0 0 0) (divBytes 255 255 255 255)
    (divBytes 252 255 255 255) (divBytes 1 0 0 0) (divBytes 255 255 255 255)
    false false true false true true
    true false false false 2 true

theorem divFreeRemainderAbsRow_satisfies :
    DivHoldsWithoutNegationRecurrence divFreeRemainderAbsRow := by
  div_witness_holds ⟨3, 3, 3, 3, 3, 3, 3, 3, by decide⟩
    negating ⟨false, false, false, false, by decide⟩

theorem divFreeRemainderAbsRow_refutes :
    ¬ DivRetiresQuotient divFreeRemainderAbsRow := by
  intro claim
  exact absurd (claim (by decide)) (by decide)

/-- The published control. -/
def divFreeRemainderMagnitude :
    MutationControl DivHoldsWithoutNegationRecurrence
      DivRetiresQuotient where
  name := "div-free-remainder-magnitude"
  witness := divFreeRemainderAbsRow
  satisfies := divFreeRemainderAbsRow_satisfies
  refutes := divFreeRemainderAbsRow_refutes

/-- The deletion is not free: no strengthening of the weakened predicate back
to `DivHolds` exists, because `DivHolds` implies the architectural claim and
the witness does not satisfy it. -/
theorem div_negation_recurrence_is_load_bearing :
    ¬ (∀ row, DivHoldsWithoutNegationRecurrence row → DivHolds row) :=
  divFreeRemainderMagnitude.strictly_weaker DivHolds div_conclusion_sound

/-! ## Control 4 — selector relabelling

Issue #137: *delete the constraint distinguishing the division result from the
remainder result; exhibit a `DIVU` row retiring the remainder.*

`result[limb] = is_division * q[limb] + (1 - is_division) * r[limb]` is the only
place where the four opcode selectors reach the retired word: everything above
it computes *both* a quotient and a remainder, and this residual chooses. The
four `destinationResultConstraints` are its limb-wise form. Delete the limb-0
member and a `DIVU` row can retire the remainder byte while every other
constraint -- including the three surviving destination residuals, which are
satisfied because the high bytes of the quotient and the remainder agree --
still holds.

Certifies the result multiplexer shared by all four selectors. The row below
exhibits it on `DIVU`; the same deletion relabels a `REM` or `REMU` row with
the quotient symmetrically, because the deleted residual is the only one that
distinguishes the two.
-/

structure DivHoldsWithoutDestinationLimb0 (row : DivRow) : Prop where
  /-- The placement residual `active - is_active` together with the four
  selector booleanity residuals: exactly one selector is set. -/
  selectorUnique :
    row.isDiv.toNat + row.isDivu.toNat + row.isRem.toNat + row.isRemu.toNat = 1
  /-- Booleanity of `special_case = zero_divisor + r_zero`. -/
  specialExclusive : row.zeroDivisor = true → row.rZero = false
  /-- `zero_divisor * rs2_next[limb] = 0`. -/
  zeroDivisorLimb0 : row.zeroDivisor = true → row.rs2Next.limb0 = 0
  zeroDivisorLimb1 : row.zeroDivisor = true → row.rs2Next.limb1 = 0
  zeroDivisorLimb2 : row.zeroDivisor = true → row.rs2Next.limb2 = 0
  zeroDivisorLimb3 : row.zeroDivisor = true → row.rs2Next.limb3 = 0
  /-- `zero_divisor * (q[limb] - 255) = 0`: the all-ones quotient. -/
  zeroDivisorQuotient0 : row.zeroDivisor = true → row.quotient.limb0 = 255
  zeroDivisorQuotient1 : row.zeroDivisor = true → row.quotient.limb1 = 255
  zeroDivisorQuotient2 : row.zeroDivisor = true → row.quotient.limb2 = 255
  zeroDivisorQuotient3 : row.zeroDivisor = true → row.quotient.limb3 = 255
  /-- `c_sum_inv` witnesses a nonzero divisor limb sum off the zero-divisor
  branch. -/
  divisorNonzero : row.zeroDivisor = false → row.rs2Next.value ≠ 0
  /-- `r_zero * r[limb] = 0`. -/
  remainderZeroLimb0 : row.rZero = true → row.remainder.limb0 = 0
  remainderZeroLimb1 : row.rZero = true → row.remainder.limb1 = 0
  remainderZeroLimb2 : row.rZero = true → row.remainder.limb2 = 0
  remainderZeroLimb3 : row.rZero = true → row.remainder.limb3 = 0
  /-- `r_sum_inv` witnesses a nonzero remainder off both special branches. -/
  remainderNonzero :
    row.zeroDivisor = false → row.rZero = false → row.remainder.value ≠ 0
  /-- `(1 - is_signed) * b_sign = 0` and `(1 - is_signed) * c_sign = 0`. -/
  unsignedDividendSign : row.isSigned = false → row.bSign = false
  unsignedDivisorSign : row.isSigned = false → row.cSign = false
  /-- `sign_xor = b_sign + c_sign - 2 * b_sign * c_sign`. -/
  signXorDefinition : row.signXor = (row.bSign != row.cSign)
  /-- `(1 - zero_divisor) * q_sum * (q_sign - sign_xor) = 0`. -/
  quotientSignMatches :
    row.zeroDivisor = false → row.quotient.value ≠ 0 → row.qSign = row.signXor
  /-- `(1 - zero_divisor) * (q_sign - sign_xor) * q_sign = 0`. -/
  quotientSignImpliesXor :
    row.zeroDivisor = false → row.qSign = true → row.signXor = true
  /-- `zero_divisor * (q_sign - is_signed) = 0`. -/
  zeroDivisorQuotientSign :
    row.zeroDivisor = true → row.qSign = row.isSigned
  /-- `(1 - sign_xor) * (r_abs[limb] - r[limb]) = 0`. -/
  absSameLimb0 : row.signXor = false → row.remainderAbs.limb0 = row.remainder.limb0
  absSameLimb1 : row.signXor = false → row.remainderAbs.limb1 = row.remainder.limb1
  absSameLimb2 : row.signXor = false → row.remainderAbs.limb2 = row.remainder.limb2
  absSameLimb3 : row.signXor = false → row.remainderAbs.limb3 = row.remainder.limb3
  /-- The two's complement negation chain used when `sign_xor = 1`. The three
  residuals per limb pin each carry to a bit, force a zero carry to zero the
  absolute limb, and (through `r_inv`) exclude the value `256`. -/
  negationRecurrence :
    row.signXor = true →
      ∃ n0 n1 n2 n3 : Bool,
        row.remainder.limb0.toNat + row.remainderAbs.limb0.toNat =
            256 * n0.toNat ∧
        n0.toNat + row.remainder.limb1.toNat + row.remainderAbs.limb1.toNat =
            256 * n1.toNat ∧
        n1.toNat + row.remainder.limb2.toNat + row.remainderAbs.limb2.toNat =
            256 * n2.toNat ∧
        n2.toNat + row.remainder.limb3.toNat + row.remainderAbs.limb3.toNat =
            256 * n3.toNat ∧
        (n0 = false → row.remainderAbs.limb0 = 0) ∧
        (n1 = false → row.remainderAbs.limb1 = 0) ∧
        (n2 = false → row.remainderAbs.limb2 = 0) ∧
        (n3 = false → row.remainderAbs.limb3 = 0) ∧
        (n1 = n0 ∨ n1 = true) ∧
        (n2 = n1 ∨ n2 = true) ∧
        (n3 = n2 ∨ n3 = true)
  /-- The eight `product_carries` residuals with their `range_check_8_11`
  carry components. This is the AIR's proof that
  `divisor * quotient + remainder = dividend` over sign-extended limbs. -/
  productRecurrence :
    ∃ k0 k1 k2 k3 k4 k5 k6 k7 : Nat,
      k0 < 2048 ∧ k1 < 2048 ∧ k2 < 2048 ∧ k3 < 2048 ∧
      k4 < 2048 ∧ k5 < 2048 ∧ k6 < 2048 ∧ k7 < 2048 ∧
      divConv0 row = row.rs1Next.limb0.toNat + 256 * k0 ∧
      k0 + divConv1 row = row.rs1Next.limb1.toNat + 256 * k1 ∧
      k1 + divConv2 row = row.rs1Next.limb2.toNat + 256 * k2 ∧
      k2 + divConv3 row = row.rs1Next.limb3.toNat + 256 * k3 ∧
      k3 + divConv4 row = divDividendHigh row + 256 * k4 ∧
      k4 + divConv5 row = divDividendHigh row + 256 * k5 ∧
      k5 + divConv6 row = divDividendHigh row + 256 * k6 ∧
      k6 + divConv7 row = divDividendHigh row + 256 * k7
  /-- `sign_range`: `2 * is_signed * (rs1_next[3] - 128 * b_sign)` is a byte,
  which pins `b_sign` to the dividend's top bit on signed rows. -/
  dividendSignBit :
    row.isSigned = true →
      row.bSign = decide (128 ≤ row.rs1Next.limb3.toNat)
  /-- `sign_range`, second component: `c_sign` is the divisor's top bit. -/
  divisorSignBit :
    row.isSigned = true →
      row.cSign = decide (128 ≤ row.rs2Next.limb3.toNat)
  /-- `quotient_sign_range`: on a signed row with a nonzero divisor that is not
  the both-negative class, `q[3] - 128 * q_sign` fits in seven bits, pinning
  `q_sign` to the quotient's top bit. -/
  quotientSignBit :
    row.isSigned = true →
      row.zeroDivisor = false →
      ¬(row.bSign = true ∧ row.cSign = true) →
      row.qSign = decide (128 ≤ row.quotient.limb3.toNat)
  /-- `active * (1 - prefixes[0]) = 0` with all markers and `special_case`
  boolean: exactly one of the five scan participants is set. -/
  scanTotal :
    row.zeroDivisor.toNat + row.rZero.toNat +
        row.ltMarker3.toNat + row.ltMarker2.toNat +
        row.ltMarker1.toNat + row.ltMarker0.toNat = 1
  /-- `(1 - prefixes[limb]) * diffs[limb] = 0`, high limb first. -/
  scanEqual3 :
    row.zeroDivisor = false → row.rZero = false → row.ltMarker3 = false →
      divCompareDiff3 row = 0
  scanEqual2 :
    row.zeroDivisor = false → row.rZero = false → row.ltMarker3 = false →
      row.ltMarker2 = false → divCompareDiff2 row = 0
  scanEqual1 :
    row.zeroDivisor = false → row.rZero = false → row.ltMarker3 = false →
      row.ltMarker2 = false → row.ltMarker1 = false → divCompareDiff1 row = 0
  scanEqual0 :
    row.zeroDivisor = false → row.rZero = false → row.ltMarker3 = false →
      row.ltMarker2 = false → row.ltMarker1 = false → row.ltMarker0 = false →
      divCompareDiff0 row = 0
  /-- `lt_markers[limb] * (lt_diff - diffs[limb]) = 0`. -/
  scanMarker3 : row.ltMarker3 = true → (row.ltDiff : Int) = divCompareDiff3 row
  scanMarker2 : row.ltMarker2 = true → (row.ltDiff : Int) = divCompareDiff2 row
  scanMarker1 : row.ltMarker1 = true → (row.ltDiff : Int) = divCompareDiff1 row
  scanMarker0 : row.ltMarker0 = true → (row.ltDiff : Int) = divCompareDiff0 row
  /-- `positive_remainder_diff`: `lt_diff - 1` is a `range_check_20` value off
  the special branches. -/
  ltDiffLower : row.zeroDivisor = false → row.rZero = false → 1 ≤ row.ltDiff
  ltDiffUpper :
    row.zeroDivisor = false → row.rZero = false → row.ltDiff ≤ 1048576
  /-- `destinationConstraints`: the write-enable witness is exact. -/
  destinationFlag : row.destinationNonzero = decide (row.rd ≠ zeroRegister)
  -- `destinationLimb0` is deliberately absent: this is the mutation.
  /-- `destinationResultConstraints`. -/
  destinationLimb1 :
    row.rdNext.limb1 =
      if row.destinationNonzero then (divResultBytes row).limb1 else 0
  destinationLimb2 :
    row.rdNext.limb2 =
      if row.destinationNonzero then (divResultBytes row).limb2 else 0
  destinationLimb3 :
    row.rdNext.limb3 =
      if row.destinationNonzero then (divResultBytes row).limb3 else 0
  /-- `readOnlyAccessConstraints` for both source registers. -/
  sourceOneLimb0 : row.rs1Next.limb0 = row.rs1Previous.limb0
  sourceOneLimb1 : row.rs1Next.limb1 = row.rs1Previous.limb1
  sourceOneLimb2 : row.rs1Next.limb2 = row.rs1Previous.limb2
  sourceOneLimb3 : row.rs1Next.limb3 = row.rs1Previous.limb3
  sourceTwoLimb0 : row.rs2Next.limb0 = row.rs2Previous.limb0
  sourceTwoLimb1 : row.rs2Next.limb1 = row.rs2Previous.limb1
  sourceTwoLimb2 : row.rs2Next.limb2 = row.rs2Previous.limb2
  sourceTwoLimb3 : row.rs2Next.limb3 = row.rs2Previous.limb3
  /-- The access-chain clock gaps, `range_check_20` on `next - previous - 1`. -/
  clockPositive : 0 < row.clock
  sourceOneClock :
    validPreviousClock row.rs1PreviousClock (accessClock row.clock 1)
  sourceTwoClock :
    validPreviousClock row.rs2PreviousClock (accessClock row.clock 2)
  destinationClock :
    validPreviousClock row.rdPreviousClock (accessClock row.clock 3)
  /-- The emitted `registers_state` program counter. -/
  nextPcResult : row.claimedNextPc = nextPc row.pc

/-- Deleting the constraint really is a deletion: every honest row still
satisfies the weakened predicate, so the control below is not a statement
about a predicate nothing satisfies. -/
theorem divHolds_weakens_destinationLimb0
    (row : DivRow)
    (holds : DivHolds row) :
    DivHoldsWithoutDestinationLimb0 row where
  selectorUnique := holds.selectorUnique
  specialExclusive := holds.specialExclusive
  zeroDivisorLimb0 := holds.zeroDivisorLimb0
  zeroDivisorLimb1 := holds.zeroDivisorLimb1
  zeroDivisorLimb2 := holds.zeroDivisorLimb2
  zeroDivisorLimb3 := holds.zeroDivisorLimb3
  zeroDivisorQuotient0 := holds.zeroDivisorQuotient0
  zeroDivisorQuotient1 := holds.zeroDivisorQuotient1
  zeroDivisorQuotient2 := holds.zeroDivisorQuotient2
  zeroDivisorQuotient3 := holds.zeroDivisorQuotient3
  divisorNonzero := holds.divisorNonzero
  remainderZeroLimb0 := holds.remainderZeroLimb0
  remainderZeroLimb1 := holds.remainderZeroLimb1
  remainderZeroLimb2 := holds.remainderZeroLimb2
  remainderZeroLimb3 := holds.remainderZeroLimb3
  remainderNonzero := holds.remainderNonzero
  unsignedDividendSign := holds.unsignedDividendSign
  unsignedDivisorSign := holds.unsignedDivisorSign
  signXorDefinition := holds.signXorDefinition
  quotientSignMatches := holds.quotientSignMatches
  quotientSignImpliesXor := holds.quotientSignImpliesXor
  zeroDivisorQuotientSign := holds.zeroDivisorQuotientSign
  absSameLimb0 := holds.absSameLimb0
  absSameLimb1 := holds.absSameLimb1
  absSameLimb2 := holds.absSameLimb2
  absSameLimb3 := holds.absSameLimb3
  negationRecurrence := holds.negationRecurrence
  productRecurrence := holds.productRecurrence
  dividendSignBit := holds.dividendSignBit
  divisorSignBit := holds.divisorSignBit
  quotientSignBit := holds.quotientSignBit
  scanTotal := holds.scanTotal
  scanEqual3 := holds.scanEqual3
  scanEqual2 := holds.scanEqual2
  scanEqual1 := holds.scanEqual1
  scanEqual0 := holds.scanEqual0
  scanMarker3 := holds.scanMarker3
  scanMarker2 := holds.scanMarker2
  scanMarker1 := holds.scanMarker1
  scanMarker0 := holds.scanMarker0
  ltDiffLower := holds.ltDiffLower
  ltDiffUpper := holds.ltDiffUpper
  destinationFlag := holds.destinationFlag
  destinationLimb1 := holds.destinationLimb1
  destinationLimb2 := holds.destinationLimb2
  destinationLimb3 := holds.destinationLimb3
  sourceOneLimb0 := holds.sourceOneLimb0
  sourceOneLimb1 := holds.sourceOneLimb1
  sourceOneLimb2 := holds.sourceOneLimb2
  sourceOneLimb3 := holds.sourceOneLimb3
  sourceTwoLimb0 := holds.sourceTwoLimb0
  sourceTwoLimb1 := holds.sourceTwoLimb1
  sourceTwoLimb2 := holds.sourceTwoLimb2
  sourceTwoLimb3 := holds.sourceTwoLimb3
  clockPositive := holds.clockPositive
  sourceOneClock := holds.sourceOneClock
  sourceTwoClock := holds.sourceTwoClock
  destinationClock := holds.destinationClock
  nextPcResult := holds.nextPcResult

/-- `DIVU x3, x1, x2` computing `7 / 3 = 2` remainder `1`, honestly, and then
retiring the remainder `1` in the destination register. The quotient and the
remainder agree in limbs 1 to 3, so the three surviving destination residuals
do not notice. -/
def divRelabelledResultRow : DivRow :=
  divWitnessRow false true false false 3 1 2
    (divBytes 7 0 0 0) (divBytes 3 0 0 0) (divBytes 2 0 0 0)
    (divBytes 1 0 0 0) (divBytes 1 0 0 0) (divBytes 1 0 0 0)
    false false false false false false
    true false false false 2 true

theorem divRelabelledResultRow_satisfies :
    DivHoldsWithoutDestinationLimb0 divRelabelledResultRow := by
  div_witness_holds ⟨0, 0, 0, 0, 0, 0, 0, 0, by decide⟩
    negating ⟨false, false, false, false, by decide⟩

theorem divRelabelledResultRow_refutes :
    ¬ DivuRetiresQuotient divRelabelledResultRow := by
  intro claim
  exact absurd (claim (by decide)) (by decide)

/-- The published control. -/
def divSelectorRelabelling :
    MutationControl DivHoldsWithoutDestinationLimb0
      DivuRetiresQuotient where
  name := "div-selector-relabelling"
  witness := divRelabelledResultRow
  satisfies := divRelabelledResultRow_satisfies
  refutes := divRelabelledResultRow_refutes

/-- The deletion is not free: no strengthening of the weakened predicate back
to `DivHolds` exists, because `DivHolds` implies the architectural claim and
the witness does not satisfy it. -/
theorem div_result_selector_is_load_bearing :
    ¬ (∀ row, DivHoldsWithoutDestinationLimb0 row → DivHolds row) :=
  divSelectorRelabelling.strictly_weaker DivHolds divu_conclusion_sound

/-! ## Control 5 — an unsigned row reading its divisor as signed

`(1 - is_signed) * c_sign = 0` is what makes `DIVU` and `REMU` unsigned: it
forces the divisor's sign-extension byte `c_hi` to zero, so the eight-limb
product chain reads `rs2_next` as a magnitude rather than as a two's complement
integer. Nothing else in the system does that -- `sign_range` only fires on
signed rows.

Delete it and a `DIVU` row may set `c_sign = 1`, extend the divisor with `0xff`
bytes, and satisfy the product chain against the *signed* reading of the same
divisor word. The row below divides `5` by `0xffffffff`. Unsigned that is
`5 / 4294967295 = 0`; read as `-1` it is `-5`, which is what the row retires.

Certifies `DIVU` and `REMU`.
-/

structure DivHoldsWithoutUnsignedDivisorSign (row : DivRow) : Prop where
  /-- The placement residual `active - is_active` together with the four
  selector booleanity residuals: exactly one selector is set. -/
  selectorUnique :
    row.isDiv.toNat + row.isDivu.toNat + row.isRem.toNat + row.isRemu.toNat = 1
  /-- Booleanity of `special_case = zero_divisor + r_zero`. -/
  specialExclusive : row.zeroDivisor = true → row.rZero = false
  /-- `zero_divisor * rs2_next[limb] = 0`. -/
  zeroDivisorLimb0 : row.zeroDivisor = true → row.rs2Next.limb0 = 0
  zeroDivisorLimb1 : row.zeroDivisor = true → row.rs2Next.limb1 = 0
  zeroDivisorLimb2 : row.zeroDivisor = true → row.rs2Next.limb2 = 0
  zeroDivisorLimb3 : row.zeroDivisor = true → row.rs2Next.limb3 = 0
  /-- `zero_divisor * (q[limb] - 255) = 0`: the all-ones quotient. -/
  zeroDivisorQuotient0 : row.zeroDivisor = true → row.quotient.limb0 = 255
  zeroDivisorQuotient1 : row.zeroDivisor = true → row.quotient.limb1 = 255
  zeroDivisorQuotient2 : row.zeroDivisor = true → row.quotient.limb2 = 255
  zeroDivisorQuotient3 : row.zeroDivisor = true → row.quotient.limb3 = 255
  /-- `c_sum_inv` witnesses a nonzero divisor limb sum off the zero-divisor
  branch. -/
  divisorNonzero : row.zeroDivisor = false → row.rs2Next.value ≠ 0
  /-- `r_zero * r[limb] = 0`. -/
  remainderZeroLimb0 : row.rZero = true → row.remainder.limb0 = 0
  remainderZeroLimb1 : row.rZero = true → row.remainder.limb1 = 0
  remainderZeroLimb2 : row.rZero = true → row.remainder.limb2 = 0
  remainderZeroLimb3 : row.rZero = true → row.remainder.limb3 = 0
  /-- `r_sum_inv` witnesses a nonzero remainder off both special branches. -/
  remainderNonzero :
    row.zeroDivisor = false → row.rZero = false → row.remainder.value ≠ 0
  /-- `(1 - is_signed) * b_sign = 0` and `(1 - is_signed) * c_sign = 0`. -/
  unsignedDividendSign : row.isSigned = false → row.bSign = false
  -- `unsignedDivisorSign` is deliberately absent: this is the mutation.
  /-- `sign_xor = b_sign + c_sign - 2 * b_sign * c_sign`. -/
  signXorDefinition : row.signXor = (row.bSign != row.cSign)
  /-- `(1 - zero_divisor) * q_sum * (q_sign - sign_xor) = 0`. -/
  quotientSignMatches :
    row.zeroDivisor = false → row.quotient.value ≠ 0 → row.qSign = row.signXor
  /-- `(1 - zero_divisor) * (q_sign - sign_xor) * q_sign = 0`. -/
  quotientSignImpliesXor :
    row.zeroDivisor = false → row.qSign = true → row.signXor = true
  /-- `zero_divisor * (q_sign - is_signed) = 0`. -/
  zeroDivisorQuotientSign :
    row.zeroDivisor = true → row.qSign = row.isSigned
  /-- `(1 - sign_xor) * (r_abs[limb] - r[limb]) = 0`. -/
  absSameLimb0 : row.signXor = false → row.remainderAbs.limb0 = row.remainder.limb0
  absSameLimb1 : row.signXor = false → row.remainderAbs.limb1 = row.remainder.limb1
  absSameLimb2 : row.signXor = false → row.remainderAbs.limb2 = row.remainder.limb2
  absSameLimb3 : row.signXor = false → row.remainderAbs.limb3 = row.remainder.limb3
  /-- The two's complement negation chain used when `sign_xor = 1`. The three
  residuals per limb pin each carry to a bit, force a zero carry to zero the
  absolute limb, and (through `r_inv`) exclude the value `256`. -/
  negationRecurrence :
    row.signXor = true →
      ∃ n0 n1 n2 n3 : Bool,
        row.remainder.limb0.toNat + row.remainderAbs.limb0.toNat =
            256 * n0.toNat ∧
        n0.toNat + row.remainder.limb1.toNat + row.remainderAbs.limb1.toNat =
            256 * n1.toNat ∧
        n1.toNat + row.remainder.limb2.toNat + row.remainderAbs.limb2.toNat =
            256 * n2.toNat ∧
        n2.toNat + row.remainder.limb3.toNat + row.remainderAbs.limb3.toNat =
            256 * n3.toNat ∧
        (n0 = false → row.remainderAbs.limb0 = 0) ∧
        (n1 = false → row.remainderAbs.limb1 = 0) ∧
        (n2 = false → row.remainderAbs.limb2 = 0) ∧
        (n3 = false → row.remainderAbs.limb3 = 0) ∧
        (n1 = n0 ∨ n1 = true) ∧
        (n2 = n1 ∨ n2 = true) ∧
        (n3 = n2 ∨ n3 = true)
  /-- The eight `product_carries` residuals with their `range_check_8_11`
  carry components. This is the AIR's proof that
  `divisor * quotient + remainder = dividend` over sign-extended limbs. -/
  productRecurrence :
    ∃ k0 k1 k2 k3 k4 k5 k6 k7 : Nat,
      k0 < 2048 ∧ k1 < 2048 ∧ k2 < 2048 ∧ k3 < 2048 ∧
      k4 < 2048 ∧ k5 < 2048 ∧ k6 < 2048 ∧ k7 < 2048 ∧
      divConv0 row = row.rs1Next.limb0.toNat + 256 * k0 ∧
      k0 + divConv1 row = row.rs1Next.limb1.toNat + 256 * k1 ∧
      k1 + divConv2 row = row.rs1Next.limb2.toNat + 256 * k2 ∧
      k2 + divConv3 row = row.rs1Next.limb3.toNat + 256 * k3 ∧
      k3 + divConv4 row = divDividendHigh row + 256 * k4 ∧
      k4 + divConv5 row = divDividendHigh row + 256 * k5 ∧
      k5 + divConv6 row = divDividendHigh row + 256 * k6 ∧
      k6 + divConv7 row = divDividendHigh row + 256 * k7
  /-- `sign_range`: `2 * is_signed * (rs1_next[3] - 128 * b_sign)` is a byte,
  which pins `b_sign` to the dividend's top bit on signed rows. -/
  dividendSignBit :
    row.isSigned = true →
      row.bSign = decide (128 ≤ row.rs1Next.limb3.toNat)
  /-- `sign_range`, second component: `c_sign` is the divisor's top bit. -/
  divisorSignBit :
    row.isSigned = true →
      row.cSign = decide (128 ≤ row.rs2Next.limb3.toNat)
  /-- `quotient_sign_range`: on a signed row with a nonzero divisor that is not
  the both-negative class, `q[3] - 128 * q_sign` fits in seven bits, pinning
  `q_sign` to the quotient's top bit. -/
  quotientSignBit :
    row.isSigned = true →
      row.zeroDivisor = false →
      ¬(row.bSign = true ∧ row.cSign = true) →
      row.qSign = decide (128 ≤ row.quotient.limb3.toNat)
  /-- `active * (1 - prefixes[0]) = 0` with all markers and `special_case`
  boolean: exactly one of the five scan participants is set. -/
  scanTotal :
    row.zeroDivisor.toNat + row.rZero.toNat +
        row.ltMarker3.toNat + row.ltMarker2.toNat +
        row.ltMarker1.toNat + row.ltMarker0.toNat = 1
  /-- `(1 - prefixes[limb]) * diffs[limb] = 0`, high limb first. -/
  scanEqual3 :
    row.zeroDivisor = false → row.rZero = false → row.ltMarker3 = false →
      divCompareDiff3 row = 0
  scanEqual2 :
    row.zeroDivisor = false → row.rZero = false → row.ltMarker3 = false →
      row.ltMarker2 = false → divCompareDiff2 row = 0
  scanEqual1 :
    row.zeroDivisor = false → row.rZero = false → row.ltMarker3 = false →
      row.ltMarker2 = false → row.ltMarker1 = false → divCompareDiff1 row = 0
  scanEqual0 :
    row.zeroDivisor = false → row.rZero = false → row.ltMarker3 = false →
      row.ltMarker2 = false → row.ltMarker1 = false → row.ltMarker0 = false →
      divCompareDiff0 row = 0
  /-- `lt_markers[limb] * (lt_diff - diffs[limb]) = 0`. -/
  scanMarker3 : row.ltMarker3 = true → (row.ltDiff : Int) = divCompareDiff3 row
  scanMarker2 : row.ltMarker2 = true → (row.ltDiff : Int) = divCompareDiff2 row
  scanMarker1 : row.ltMarker1 = true → (row.ltDiff : Int) = divCompareDiff1 row
  scanMarker0 : row.ltMarker0 = true → (row.ltDiff : Int) = divCompareDiff0 row
  /-- `positive_remainder_diff`: `lt_diff - 1` is a `range_check_20` value off
  the special branches. -/
  ltDiffLower : row.zeroDivisor = false → row.rZero = false → 1 ≤ row.ltDiff
  ltDiffUpper :
    row.zeroDivisor = false → row.rZero = false → row.ltDiff ≤ 1048576
  /-- `destinationConstraints`: the write-enable witness is exact. -/
  destinationFlag : row.destinationNonzero = decide (row.rd ≠ zeroRegister)
  /-- `destinationResultConstraints`. -/
  destinationLimb0 :
    row.rdNext.limb0 =
      if row.destinationNonzero then (divResultBytes row).limb0 else 0
  destinationLimb1 :
    row.rdNext.limb1 =
      if row.destinationNonzero then (divResultBytes row).limb1 else 0
  destinationLimb2 :
    row.rdNext.limb2 =
      if row.destinationNonzero then (divResultBytes row).limb2 else 0
  destinationLimb3 :
    row.rdNext.limb3 =
      if row.destinationNonzero then (divResultBytes row).limb3 else 0
  /-- `readOnlyAccessConstraints` for both source registers. -/
  sourceOneLimb0 : row.rs1Next.limb0 = row.rs1Previous.limb0
  sourceOneLimb1 : row.rs1Next.limb1 = row.rs1Previous.limb1
  sourceOneLimb2 : row.rs1Next.limb2 = row.rs1Previous.limb2
  sourceOneLimb3 : row.rs1Next.limb3 = row.rs1Previous.limb3
  sourceTwoLimb0 : row.rs2Next.limb0 = row.rs2Previous.limb0
  sourceTwoLimb1 : row.rs2Next.limb1 = row.rs2Previous.limb1
  sourceTwoLimb2 : row.rs2Next.limb2 = row.rs2Previous.limb2
  sourceTwoLimb3 : row.rs2Next.limb3 = row.rs2Previous.limb3
  /-- The access-chain clock gaps, `range_check_20` on `next - previous - 1`. -/
  clockPositive : 0 < row.clock
  sourceOneClock :
    validPreviousClock row.rs1PreviousClock (accessClock row.clock 1)
  sourceTwoClock :
    validPreviousClock row.rs2PreviousClock (accessClock row.clock 2)
  destinationClock :
    validPreviousClock row.rdPreviousClock (accessClock row.clock 3)
  /-- The emitted `registers_state` program counter. -/
  nextPcResult : row.claimedNextPc = nextPc row.pc

/-- Deleting the constraint really is a deletion: every honest row still
satisfies the weakened predicate, so the control below is not a statement
about a predicate nothing satisfies. -/
theorem divHolds_weakens_unsignedDivisorSign
    (row : DivRow)
    (holds : DivHolds row) :
    DivHoldsWithoutUnsignedDivisorSign row where
  selectorUnique := holds.selectorUnique
  specialExclusive := holds.specialExclusive
  zeroDivisorLimb0 := holds.zeroDivisorLimb0
  zeroDivisorLimb1 := holds.zeroDivisorLimb1
  zeroDivisorLimb2 := holds.zeroDivisorLimb2
  zeroDivisorLimb3 := holds.zeroDivisorLimb3
  zeroDivisorQuotient0 := holds.zeroDivisorQuotient0
  zeroDivisorQuotient1 := holds.zeroDivisorQuotient1
  zeroDivisorQuotient2 := holds.zeroDivisorQuotient2
  zeroDivisorQuotient3 := holds.zeroDivisorQuotient3
  divisorNonzero := holds.divisorNonzero
  remainderZeroLimb0 := holds.remainderZeroLimb0
  remainderZeroLimb1 := holds.remainderZeroLimb1
  remainderZeroLimb2 := holds.remainderZeroLimb2
  remainderZeroLimb3 := holds.remainderZeroLimb3
  remainderNonzero := holds.remainderNonzero
  unsignedDividendSign := holds.unsignedDividendSign
  signXorDefinition := holds.signXorDefinition
  quotientSignMatches := holds.quotientSignMatches
  quotientSignImpliesXor := holds.quotientSignImpliesXor
  zeroDivisorQuotientSign := holds.zeroDivisorQuotientSign
  absSameLimb0 := holds.absSameLimb0
  absSameLimb1 := holds.absSameLimb1
  absSameLimb2 := holds.absSameLimb2
  absSameLimb3 := holds.absSameLimb3
  negationRecurrence := holds.negationRecurrence
  productRecurrence := holds.productRecurrence
  dividendSignBit := holds.dividendSignBit
  divisorSignBit := holds.divisorSignBit
  quotientSignBit := holds.quotientSignBit
  scanTotal := holds.scanTotal
  scanEqual3 := holds.scanEqual3
  scanEqual2 := holds.scanEqual2
  scanEqual1 := holds.scanEqual1
  scanEqual0 := holds.scanEqual0
  scanMarker3 := holds.scanMarker3
  scanMarker2 := holds.scanMarker2
  scanMarker1 := holds.scanMarker1
  scanMarker0 := holds.scanMarker0
  ltDiffLower := holds.ltDiffLower
  ltDiffUpper := holds.ltDiffUpper
  destinationFlag := holds.destinationFlag
  destinationLimb0 := holds.destinationLimb0
  destinationLimb1 := holds.destinationLimb1
  destinationLimb2 := holds.destinationLimb2
  destinationLimb3 := holds.destinationLimb3
  sourceOneLimb0 := holds.sourceOneLimb0
  sourceOneLimb1 := holds.sourceOneLimb1
  sourceOneLimb2 := holds.sourceOneLimb2
  sourceOneLimb3 := holds.sourceOneLimb3
  sourceTwoLimb0 := holds.sourceTwoLimb0
  sourceTwoLimb1 := holds.sourceTwoLimb1
  sourceTwoLimb2 := holds.sourceTwoLimb2
  sourceTwoLimb3 := holds.sourceTwoLimb3
  clockPositive := holds.clockPositive
  sourceOneClock := holds.sourceOneClock
  sourceTwoClock := holds.sourceTwoClock
  destinationClock := holds.destinationClock
  nextPcResult := holds.nextPcResult

/-- `DIVU x3, x1, x2` dividing `5` by `0xffffffff`. With the divisor's sign
witness released the row extends the divisor to `-1` over eight limbs and
commits the quotient `0xfffffffb = -5`, with a zero remainder. Every product
carry stays inside its eleven-bit `range_check_8_11` window (the largest is
`2035 < 2048`), the remainder is zero so the comparison scan is parked on
`r_zero`, and `sign_xor` and `q_sign` are consistent with the forged divisor
sign. -/
def divuSignedDivisorRow : DivRow :=
  divWitnessRow false true false false 3 1 2
    (divBytes 5 0 0 0) (divBytes 255 255 255 255) (divBytes 251 255 255 255)
    (divBytes 0 0 0 0) (divBytes 0 0 0 0) (divBytes 251 255 255 255)
    false true false true true true
    false false false false 0 true

theorem divuSignedDivisorRow_satisfies :
    DivHoldsWithoutUnsignedDivisorSign divuSignedDivisorRow := by
  div_witness_holds ⟨250, 505, 760, 1015, 1270, 1525, 1780, 2035, by decide⟩
    negating ⟨false, false, false, false, by decide⟩

theorem divuSignedDivisorRow_refutes :
    ¬ DivuRetiresQuotient divuSignedDivisorRow := by
  intro claim
  exact absurd (claim (by decide)) (by decide)

/-- The published control. -/
def divuSignedDivisor :
    MutationControl DivHoldsWithoutUnsignedDivisorSign
      DivuRetiresQuotient where
  name := "divu-signed-divisor"
  witness := divuSignedDivisorRow
  satisfies := divuSignedDivisorRow_satisfies
  refutes := divuSignedDivisorRow_refutes

/-- The deletion is not free: no strengthening of the weakened predicate back
to `DivHolds` exists, because `DivHolds` implies the architectural claim and
the witness does not satisfy it. -/
theorem divu_divisor_sign_is_load_bearing :
    ¬ (∀ row, DivHoldsWithoutUnsignedDivisorSign row → DivHolds row) :=
  divuSignedDivisor.strictly_weaker DivHolds divu_conclusion_sound

/-! ## Control 6 — a free `sign_xor`, and with it a free quotient sign

Issue #137 asks for a *free quotient sign* control. The two residuals that tie
`q_sign` directly to `sign_xor` -- `(1 - zero_divisor) * q_sum * (q_sign -
sign_xor) = 0` and `(1 - zero_divisor) * (q_sign - sign_xor) * q_sign = 0` --
have no control at all, and the reason is recorded at the end of this file.
The load-bearing member of that group is the residual one level up: `sign_xor =
b_sign + c_sign - 2 * b_sign * c_sign`, the definition that ties `sign_xor` to
the operand signs. Free it and `q_sign` follows it anywhere, because the two
residuals above only ever compare the two witnesses with each other.

The row below is a `DIVU` row with `b_sign = c_sign = 0`, as
`(1 - is_signed) * sign = 0` requires, but with `sign_xor = 1` anyway. That
switches the remainder from the `(1 - sign_xor) * (r_abs - r) = 0` branch to the
two's complement branch, so a remainder just below `2 ^ 32` now presents a tiny
`r_abs` to the comparison scan, and `q_sign = 1` extends the quotient with
`0xff` bytes. `7 / 5` retires as `0xcccccccf`.

Certifies `DIV`, `DIVU`, `REM` and `REMU`: `sign_xor` is selector-independent
and every branch of the remainder handling is gated on it.
-/

structure DivHoldsWithoutSignXorDefinition (row : DivRow) : Prop where
  /-- The placement residual `active - is_active` together with the four
  selector booleanity residuals: exactly one selector is set. -/
  selectorUnique :
    row.isDiv.toNat + row.isDivu.toNat + row.isRem.toNat + row.isRemu.toNat = 1
  /-- Booleanity of `special_case = zero_divisor + r_zero`. -/
  specialExclusive : row.zeroDivisor = true → row.rZero = false
  /-- `zero_divisor * rs2_next[limb] = 0`. -/
  zeroDivisorLimb0 : row.zeroDivisor = true → row.rs2Next.limb0 = 0
  zeroDivisorLimb1 : row.zeroDivisor = true → row.rs2Next.limb1 = 0
  zeroDivisorLimb2 : row.zeroDivisor = true → row.rs2Next.limb2 = 0
  zeroDivisorLimb3 : row.zeroDivisor = true → row.rs2Next.limb3 = 0
  /-- `zero_divisor * (q[limb] - 255) = 0`: the all-ones quotient. -/
  zeroDivisorQuotient0 : row.zeroDivisor = true → row.quotient.limb0 = 255
  zeroDivisorQuotient1 : row.zeroDivisor = true → row.quotient.limb1 = 255
  zeroDivisorQuotient2 : row.zeroDivisor = true → row.quotient.limb2 = 255
  zeroDivisorQuotient3 : row.zeroDivisor = true → row.quotient.limb3 = 255
  /-- `c_sum_inv` witnesses a nonzero divisor limb sum off the zero-divisor
  branch. -/
  divisorNonzero : row.zeroDivisor = false → row.rs2Next.value ≠ 0
  /-- `r_zero * r[limb] = 0`. -/
  remainderZeroLimb0 : row.rZero = true → row.remainder.limb0 = 0
  remainderZeroLimb1 : row.rZero = true → row.remainder.limb1 = 0
  remainderZeroLimb2 : row.rZero = true → row.remainder.limb2 = 0
  remainderZeroLimb3 : row.rZero = true → row.remainder.limb3 = 0
  /-- `r_sum_inv` witnesses a nonzero remainder off both special branches. -/
  remainderNonzero :
    row.zeroDivisor = false → row.rZero = false → row.remainder.value ≠ 0
  /-- `(1 - is_signed) * b_sign = 0` and `(1 - is_signed) * c_sign = 0`. -/
  unsignedDividendSign : row.isSigned = false → row.bSign = false
  unsignedDivisorSign : row.isSigned = false → row.cSign = false
  -- `signXorDefinition` is deliberately absent: this is the mutation.
  -- `sign_xor = b_sign + c_sign - 2 * b_sign * c_sign`.
  /-- `(1 - zero_divisor) * q_sum * (q_sign - sign_xor) = 0`. -/
  quotientSignMatches :
    row.zeroDivisor = false → row.quotient.value ≠ 0 → row.qSign = row.signXor
  /-- `(1 - zero_divisor) * (q_sign - sign_xor) * q_sign = 0`. -/
  quotientSignImpliesXor :
    row.zeroDivisor = false → row.qSign = true → row.signXor = true
  /-- `zero_divisor * (q_sign - is_signed) = 0`. -/
  zeroDivisorQuotientSign :
    row.zeroDivisor = true → row.qSign = row.isSigned
  /-- `(1 - sign_xor) * (r_abs[limb] - r[limb]) = 0`. -/
  absSameLimb0 : row.signXor = false → row.remainderAbs.limb0 = row.remainder.limb0
  absSameLimb1 : row.signXor = false → row.remainderAbs.limb1 = row.remainder.limb1
  absSameLimb2 : row.signXor = false → row.remainderAbs.limb2 = row.remainder.limb2
  absSameLimb3 : row.signXor = false → row.remainderAbs.limb3 = row.remainder.limb3
  /-- The two's complement negation chain used when `sign_xor = 1`. The three
  residuals per limb pin each carry to a bit, force a zero carry to zero the
  absolute limb, and (through `r_inv`) exclude the value `256`. -/
  negationRecurrence :
    row.signXor = true →
      ∃ n0 n1 n2 n3 : Bool,
        row.remainder.limb0.toNat + row.remainderAbs.limb0.toNat =
            256 * n0.toNat ∧
        n0.toNat + row.remainder.limb1.toNat + row.remainderAbs.limb1.toNat =
            256 * n1.toNat ∧
        n1.toNat + row.remainder.limb2.toNat + row.remainderAbs.limb2.toNat =
            256 * n2.toNat ∧
        n2.toNat + row.remainder.limb3.toNat + row.remainderAbs.limb3.toNat =
            256 * n3.toNat ∧
        (n0 = false → row.remainderAbs.limb0 = 0) ∧
        (n1 = false → row.remainderAbs.limb1 = 0) ∧
        (n2 = false → row.remainderAbs.limb2 = 0) ∧
        (n3 = false → row.remainderAbs.limb3 = 0) ∧
        (n1 = n0 ∨ n1 = true) ∧
        (n2 = n1 ∨ n2 = true) ∧
        (n3 = n2 ∨ n3 = true)
  /-- The eight `product_carries` residuals with their `range_check_8_11`
  carry components. This is the AIR's proof that
  `divisor * quotient + remainder = dividend` over sign-extended limbs. -/
  productRecurrence :
    ∃ k0 k1 k2 k3 k4 k5 k6 k7 : Nat,
      k0 < 2048 ∧ k1 < 2048 ∧ k2 < 2048 ∧ k3 < 2048 ∧
      k4 < 2048 ∧ k5 < 2048 ∧ k6 < 2048 ∧ k7 < 2048 ∧
      divConv0 row = row.rs1Next.limb0.toNat + 256 * k0 ∧
      k0 + divConv1 row = row.rs1Next.limb1.toNat + 256 * k1 ∧
      k1 + divConv2 row = row.rs1Next.limb2.toNat + 256 * k2 ∧
      k2 + divConv3 row = row.rs1Next.limb3.toNat + 256 * k3 ∧
      k3 + divConv4 row = divDividendHigh row + 256 * k4 ∧
      k4 + divConv5 row = divDividendHigh row + 256 * k5 ∧
      k5 + divConv6 row = divDividendHigh row + 256 * k6 ∧
      k6 + divConv7 row = divDividendHigh row + 256 * k7
  /-- `sign_range`: `2 * is_signed * (rs1_next[3] - 128 * b_sign)` is a byte,
  which pins `b_sign` to the dividend's top bit on signed rows. -/
  dividendSignBit :
    row.isSigned = true →
      row.bSign = decide (128 ≤ row.rs1Next.limb3.toNat)
  /-- `sign_range`, second component: `c_sign` is the divisor's top bit. -/
  divisorSignBit :
    row.isSigned = true →
      row.cSign = decide (128 ≤ row.rs2Next.limb3.toNat)
  /-- `quotient_sign_range`: on a signed row with a nonzero divisor that is not
  the both-negative class, `q[3] - 128 * q_sign` fits in seven bits, pinning
  `q_sign` to the quotient's top bit. -/
  quotientSignBit :
    row.isSigned = true →
      row.zeroDivisor = false →
      ¬(row.bSign = true ∧ row.cSign = true) →
      row.qSign = decide (128 ≤ row.quotient.limb3.toNat)
  /-- `active * (1 - prefixes[0]) = 0` with all markers and `special_case`
  boolean: exactly one of the five scan participants is set. -/
  scanTotal :
    row.zeroDivisor.toNat + row.rZero.toNat +
        row.ltMarker3.toNat + row.ltMarker2.toNat +
        row.ltMarker1.toNat + row.ltMarker0.toNat = 1
  /-- `(1 - prefixes[limb]) * diffs[limb] = 0`, high limb first. -/
  scanEqual3 :
    row.zeroDivisor = false → row.rZero = false → row.ltMarker3 = false →
      divCompareDiff3 row = 0
  scanEqual2 :
    row.zeroDivisor = false → row.rZero = false → row.ltMarker3 = false →
      row.ltMarker2 = false → divCompareDiff2 row = 0
  scanEqual1 :
    row.zeroDivisor = false → row.rZero = false → row.ltMarker3 = false →
      row.ltMarker2 = false → row.ltMarker1 = false → divCompareDiff1 row = 0
  scanEqual0 :
    row.zeroDivisor = false → row.rZero = false → row.ltMarker3 = false →
      row.ltMarker2 = false → row.ltMarker1 = false → row.ltMarker0 = false →
      divCompareDiff0 row = 0
  /-- `lt_markers[limb] * (lt_diff - diffs[limb]) = 0`. -/
  scanMarker3 : row.ltMarker3 = true → (row.ltDiff : Int) = divCompareDiff3 row
  scanMarker2 : row.ltMarker2 = true → (row.ltDiff : Int) = divCompareDiff2 row
  scanMarker1 : row.ltMarker1 = true → (row.ltDiff : Int) = divCompareDiff1 row
  scanMarker0 : row.ltMarker0 = true → (row.ltDiff : Int) = divCompareDiff0 row
  /-- `positive_remainder_diff`: `lt_diff - 1` is a `range_check_20` value off
  the special branches. -/
  ltDiffLower : row.zeroDivisor = false → row.rZero = false → 1 ≤ row.ltDiff
  ltDiffUpper :
    row.zeroDivisor = false → row.rZero = false → row.ltDiff ≤ 1048576
  /-- `destinationConstraints`: the write-enable witness is exact. -/
  destinationFlag : row.destinationNonzero = decide (row.rd ≠ zeroRegister)
  /-- `destinationResultConstraints`. -/
  destinationLimb0 :
    row.rdNext.limb0 =
      if row.destinationNonzero then (divResultBytes row).limb0 else 0
  destinationLimb1 :
    row.rdNext.limb1 =
      if row.destinationNonzero then (divResultBytes row).limb1 else 0
  destinationLimb2 :
    row.rdNext.limb2 =
      if row.destinationNonzero then (divResultBytes row).limb2 else 0
  destinationLimb3 :
    row.rdNext.limb3 =
      if row.destinationNonzero then (divResultBytes row).limb3 else 0
  /-- `readOnlyAccessConstraints` for both source registers. -/
  sourceOneLimb0 : row.rs1Next.limb0 = row.rs1Previous.limb0
  sourceOneLimb1 : row.rs1Next.limb1 = row.rs1Previous.limb1
  sourceOneLimb2 : row.rs1Next.limb2 = row.rs1Previous.limb2
  sourceOneLimb3 : row.rs1Next.limb3 = row.rs1Previous.limb3
  sourceTwoLimb0 : row.rs2Next.limb0 = row.rs2Previous.limb0
  sourceTwoLimb1 : row.rs2Next.limb1 = row.rs2Previous.limb1
  sourceTwoLimb2 : row.rs2Next.limb2 = row.rs2Previous.limb2
  sourceTwoLimb3 : row.rs2Next.limb3 = row.rs2Previous.limb3
  /-- The access-chain clock gaps, `range_check_20` on `next - previous - 1`. -/
  clockPositive : 0 < row.clock
  sourceOneClock :
    validPreviousClock row.rs1PreviousClock (accessClock row.clock 1)
  sourceTwoClock :
    validPreviousClock row.rs2PreviousClock (accessClock row.clock 2)
  destinationClock :
    validPreviousClock row.rdPreviousClock (accessClock row.clock 3)
  /-- The emitted `registers_state` program counter. -/
  nextPcResult : row.claimedNextPc = nextPc row.pc

/-- Deleting the constraint really is a deletion: every honest row still
satisfies the weakened predicate, so the control below is not a statement
about a predicate nothing satisfies. -/
theorem divHolds_weakens_signXorDefinition
    (row : DivRow)
    (holds : DivHolds row) :
    DivHoldsWithoutSignXorDefinition row where
  selectorUnique := holds.selectorUnique
  specialExclusive := holds.specialExclusive
  zeroDivisorLimb0 := holds.zeroDivisorLimb0
  zeroDivisorLimb1 := holds.zeroDivisorLimb1
  zeroDivisorLimb2 := holds.zeroDivisorLimb2
  zeroDivisorLimb3 := holds.zeroDivisorLimb3
  zeroDivisorQuotient0 := holds.zeroDivisorQuotient0
  zeroDivisorQuotient1 := holds.zeroDivisorQuotient1
  zeroDivisorQuotient2 := holds.zeroDivisorQuotient2
  zeroDivisorQuotient3 := holds.zeroDivisorQuotient3
  divisorNonzero := holds.divisorNonzero
  remainderZeroLimb0 := holds.remainderZeroLimb0
  remainderZeroLimb1 := holds.remainderZeroLimb1
  remainderZeroLimb2 := holds.remainderZeroLimb2
  remainderZeroLimb3 := holds.remainderZeroLimb3
  remainderNonzero := holds.remainderNonzero
  unsignedDividendSign := holds.unsignedDividendSign
  unsignedDivisorSign := holds.unsignedDivisorSign
  quotientSignMatches := holds.quotientSignMatches
  quotientSignImpliesXor := holds.quotientSignImpliesXor
  zeroDivisorQuotientSign := holds.zeroDivisorQuotientSign
  absSameLimb0 := holds.absSameLimb0
  absSameLimb1 := holds.absSameLimb1
  absSameLimb2 := holds.absSameLimb2
  absSameLimb3 := holds.absSameLimb3
  negationRecurrence := holds.negationRecurrence
  productRecurrence := holds.productRecurrence
  dividendSignBit := holds.dividendSignBit
  divisorSignBit := holds.divisorSignBit
  quotientSignBit := holds.quotientSignBit
  scanTotal := holds.scanTotal
  scanEqual3 := holds.scanEqual3
  scanEqual2 := holds.scanEqual2
  scanEqual1 := holds.scanEqual1
  scanEqual0 := holds.scanEqual0
  scanMarker3 := holds.scanMarker3
  scanMarker2 := holds.scanMarker2
  scanMarker1 := holds.scanMarker1
  scanMarker0 := holds.scanMarker0
  ltDiffLower := holds.ltDiffLower
  ltDiffUpper := holds.ltDiffUpper
  destinationFlag := holds.destinationFlag
  destinationLimb0 := holds.destinationLimb0
  destinationLimb1 := holds.destinationLimb1
  destinationLimb2 := holds.destinationLimb2
  destinationLimb3 := holds.destinationLimb3
  sourceOneLimb0 := holds.sourceOneLimb0
  sourceOneLimb1 := holds.sourceOneLimb1
  sourceOneLimb2 := holds.sourceOneLimb2
  sourceOneLimb3 := holds.sourceOneLimb3
  sourceTwoLimb0 := holds.sourceTwoLimb0
  sourceTwoLimb1 := holds.sourceTwoLimb1
  sourceTwoLimb2 := holds.sourceTwoLimb2
  sourceTwoLimb3 := holds.sourceTwoLimb3
  clockPositive := holds.clockPositive
  sourceOneClock := holds.sourceOneClock
  sourceTwoClock := holds.sourceTwoClock
  destinationClock := holds.destinationClock
  nextPcResult := holds.nextPcResult

/-- `DIVU x3, x1, x2` dividing `7` by `5`, with `sign_xor` set on a row whose
two operand sign witnesses are both clear. The committed remainder is
`0xfffffffc`, whose two's complement magnitude `4` passes the scan against the
divisor `5`; the committed quotient `0xcccccccf` with `q_sign = 1` then
satisfies all eight product residuals with carries of `5`. The architectural
answer is `1`. -/
def divuFreeSignXorRow : DivRow :=
  divWitnessRow false true false false 3 1 2
    (divBytes 7 0 0 0) (divBytes 5 0 0 0) (divBytes 207 204 204 204)
    (divBytes 252 255 255 255) (divBytes 4 0 0 0) (divBytes 207 204 204 204)
    false false false false true true
    true false false false 1 true

theorem divuFreeSignXorRow_satisfies :
    DivHoldsWithoutSignXorDefinition divuFreeSignXorRow := by
  div_witness_holds ⟨5, 5, 5, 5, 5, 5, 5, 5, by decide⟩
    negating ⟨true, true, true, true, by decide⟩

theorem divuFreeSignXorRow_refutes :
    ¬ DivuRetiresQuotient divuFreeSignXorRow := by
  intro claim
  exact absurd (claim (by decide)) (by decide)

/-- The published control. -/
def divuFreeSignXor :
    MutationControl DivHoldsWithoutSignXorDefinition
      DivuRetiresQuotient where
  name := "div-free-sign-xor"
  witness := divuFreeSignXorRow
  satisfies := divuFreeSignXorRow_satisfies
  refutes := divuFreeSignXorRow_refutes

/-- The deletion is not free: no strengthening of the weakened predicate back
to `DivHolds` exists, because `DivHolds` implies the architectural claim and
the witness does not satisfy it. -/
theorem div_sign_xor_definition_is_load_bearing :
    ¬ (∀ row, DivHoldsWithoutSignXorDefinition row → DivHolds row) :=
  divuFreeSignXor.strictly_weaker DivHolds divu_conclusion_sound

/-! ## The architectural side of the six counterexamples -/

/-- Every counterexample above, audited against `Arith/Division.lean`. Each
pair is the value the ISA requires of the row's operands followed by the word
the witness actually retires; the two differ in all six cases. This is the
same cross-check `divWitness_architectural_agreement` performs for the honest
witnesses, and it keeps the controls readable without unfolding a row. -/
theorem divMutation_architectural_answers :
    (Arith.divideUnsigned (BitVec.ofNat 32 7) zeroWord = Arith.allOnesWord ∧
        divFreeZeroQuotientRow.rdNext.word = BitVec.ofNat 32 0xffffff00) ∧
      (Arith.divideUnsigned (BitVec.ofNat 32 6) (BitVec.ofNat 32 3) =
            BitVec.ofNat 32 2 ∧
        divSlackScanRow.rdNext.word = BitVec.ofNat 32 1) ∧
      (Arith.divideSigned (BitVec.ofNat 32 4294967289) (BitVec.ofNat 32 3) =
            BitVec.ofNat 32 4294967294 ∧
        divFreeRemainderAbsRow.rdNext.word = BitVec.ofNat 32 4294967295) ∧
      (Arith.divideUnsigned (BitVec.ofNat 32 7) (BitVec.ofNat 32 3) =
            BitVec.ofNat 32 2 ∧
        divRelabelledResultRow.rdNext.word = BitVec.ofNat 32 1) ∧
      (Arith.divideUnsigned (BitVec.ofNat 32 5) (BitVec.ofNat 32 4294967295) =
            zeroWord ∧
        divuSignedDivisorRow.rdNext.word = BitVec.ofNat 32 4294967291) ∧
      (Arith.divideUnsigned (BitVec.ofNat 32 7) (BitVec.ofNat 32 5) =
            BitVec.ofNat 32 1 ∧
        divuFreeSignXorRow.rdNext.word = BitVec.ofNat 32 0xcccccccf) := by
  decide

/-! ## Two deletions with no control, and why

Issue #137 also names a *free quotient sign* mutation and a *non-byte divisor
limb* mutation. Neither can be turned into a `MutationControl`, and in both
cases the obstruction is a fact about the system rather than a gap in this file.

**Free quotient sign.** Three residuals bear on `q_sign`:
`quotientSignMatches` (`(1 - zero_divisor) * q_sum * (q_sign - sign_xor) = 0`),
`quotientSignImpliesXor` (`(1 - zero_divisor) * (q_sign - sign_xor) * q_sign =
0`), and the `quotient_sign_range` lookup transcribed as `quotientSignBit`.

The first and the third are consumed by no theorem of `Air/Family/Div.lean` at
all, and a control for a field the derivation never reads cannot exist:
`refutes` would have to exhibit a row on which the conclusion fails, but the
conclusion is derived without the field, so every row satisfying the weakened
predicate satisfies it. The reason the derivation can ignore them is
`div_wrap_signed_int` -- the retired word is `q_sign`-independent, because
wrapping `q.value - 2 ^ 32 * q_sign` back to 32 bits erases the witness --
together with `div_signed_result`, which pins the signed reading of the
quotient from the product chain and the comparison scan alone.

The second is read once, by `div_unsigned_signs`, and no counterexample to its
deletion was found either: `quotientSignMatches` survives that deletion and
forces `q_sum = 0` on any row with `q_sign` and `sign_xor` apart, and a zero
quotient with `q_sign = 1` turns the eight product residuals into
`c_ext * (2 ^ 64 - 2 ^ 32) + r_ext = b_ext` modulo `2 ^ 64`, which has no
solution for a divisor the `c_sum_inv` witness already forces nonzero. That
last argument is by hand rather than machine-checked. What is machine-checked
is Control 6, which frees `sign_xor` one level up and lets `q_sign` follow it.

**Non-byte divisor limb.** The `range_check_8_8` component on `rs2_next` is not
a field of `DivHolds`. Per the transcription convention recorded at the head of
`Air/Family/Div.lean`, a column carrying a byte range lookup is *typed*
`BitVec 8`, so the range is carried by the column type of `DivRow` and there is
no field to delete. Exhibiting a divisor limb at or above `256` would require a
second row type whose divisor limbs are field elements, and a re-transcription
of every residual that mentions them -- the eight convolution limbs, the four
comparison differences, the zero-divisor limb residuals and the read-only
residuals. That is a change to the family capsule, which this file does not
own.
-/

end RiscvRefinement.Opcodes
