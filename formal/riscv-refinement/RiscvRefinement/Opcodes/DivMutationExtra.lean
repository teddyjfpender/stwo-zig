-- REVIEWED-CAPSULE BOUNDARY. Hand-written file; not generated, and not a
-- generated-Sail theorem. The architectural conclusions these mutation
-- controls certify are stated via Arith.remainderSigned /
-- Arith.remainderUnsigned of RiscvRefinement/Arith/Division.lean -- the
-- arithmetic the reviewed normalized capsule RiscvRefinement/Sail/Reviewed/
-- Div.lean fixes, which is hand-written with no generator, no digest, and no
-- derivation from any Sail artifact (see its header). Nothing in this file is
-- publication-level for the architectural side.

import RiscvRefinement.Air.Family.Div
import RiscvRefinement.Mutation
import RiscvRefinement.Opcodes.Div
import RiscvRefinement.Opcodes.DivMutation

/-!
# Load-bearing mutation controls for `REM` and `REMU`

`Opcodes/DivMutation.lean` carries six controls for the DIV family, and every
one of them exhibits its counterexample on a `DIV` or a `DIVU` row. That is
family-level evidence: it certifies residuals `REM` and `REMU` also consume, but
no witness there carries the `is_rem` or `is_remu` selector, and per-opcode
credit on the strength of a sibling's witness is exactly what was refused for
`lb`, `lw`, `lbu` and `lhu`. This file supplies the missing witnesses.

## What is actually different about the remainder selectors

Everything above the result multiplexer is shared: one product recurrence, one
comparison scan, one sign-extension discipline, computing *both* a quotient and
a remainder on every row. The four selectors part company at exactly one
residual,

  `result[limb] = is_division * q[limb] + (1 - is_division) * r[limb]`,

so `REM` and `REMU` retire `r` where `DIV` and `DIVU` retire `q`. Two
consequences drive the controls below.

* The zero-divisor convention is **inverted**, not shared. `DIV` and `DIVU` by
  zero yield all ones and four dedicated residuals
  `zero_divisor * (q[limb] - 255) = 0` commit that. `REM` and `REMU` by zero
  yield the **dividend**, and there is no residual that says so: the claim is
  carried by the eight product residuals collapsing to `remainder = dividend`
  once `zero_divisor * rs2_next[limb] = 0` has zeroed every divisor limb.
  Control 3 deletes what actually carries the convention rather than the
  residuals that carry the *other* branch's convention -- deleting
  `zeroDivisorQuotient0` here would produce a row whose retired remainder is
  still architecturally correct, i.e. no control at all.
* The remainder's sign is the **dividend's**, not the quotient's:
  `rem(-100, 7) = -2`, never `+5` and never `+2`. Control 1 is the deletion
  that frees it.

## Discipline

Following `Opcodes/DivMutation.lean`, the soundness side is discharged here
rather than assumed: `rem_conclusion_sound` and `remu_conclusion_sound` prove
each conclusion from the *unweakened* `DivHolds`, so every
`..._is_load_bearing` corollary below is unconditional.

Each conclusion is row-parameterised (never a literal constant), guarded on the
row's own selector (`row.isRem` / `row.isRemu`), and stated purely in terms of
`Arith/Division.lean` applied to the words the row consumed on the source
register buses. None of them restates a deleted constraint, so none is
circular.

Controls 2 and 4 reuse the weakened predicates `DivHoldsWithoutScanTotal` and
`DivHoldsWithoutDestinationLimb0` already defined in `Opcodes/DivMutation.lean`
rather than re-transcribing them. The deletion is the same; the witness, the
selector it carries and the architectural conclusion it refutes are new, which
is precisely the per-opcode evidence that was missing.
-/

namespace RiscvRefinement.Opcodes

open RiscvRefinement
open RiscvRefinement.Air.Family
open RiscvRefinement.Mutation

/-! ## The architectural conclusions -/

/-- The architectural claim `rem_refines` reaches on a `REM` row: the word
emitted on the destination register bus is the RISC-V signed truncating
remainder of the two words consumed on the source register buses. -/
def RemRetiresRemainder (row : DivRow) : Prop :=
  row.isRem = true →
    row.rdNext.word =
      architecturalValue row.rd
        (Arith.remainderSigned row.rs1Previous.word row.rs2Previous.word)

/-- The same claim on a `REMU` row, against the unsigned remainder. -/
def RemuRetiresRemainder (row : DivRow) : Prop :=
  row.isRemu = true →
    row.rdNext.word =
      architecturalValue row.rd
        (Arith.remainderUnsigned row.rs1Previous.word row.rs2Previous.word)

/-- Soundness of the signed remainder conclusion, from the unweakened row
predicate. Every step is a lemma of the family capsule: `div_flags_rem` reads
the selector into `is_signed = 1` and `is_division = 0`, so the result
multiplexer selects `r`; `rem_result_word` derives the remainder from the
product chain, the sign lookups and the comparison scan; the read-only
residuals identify the consumed words with the computed limbs; and
`div_destination_word` carries the result to the destination bus. -/
theorem rem_conclusion_sound (row : DivRow) (holds : DivHolds row) :
    RemRetiresRemainder row := by
  intro selector
  obtain ⟨signed, division⟩ := div_flags_rem row holds selector
  have result : divResultBytes row = row.remainder := by
    simp [divResultBytes, division]
  rw [div_destination_word row holds, result,
    rem_result_word row holds signed, div_source_one_word row holds,
    div_source_two_word row holds]

/-- Soundness of the unsigned remainder conclusion. -/
theorem remu_conclusion_sound (row : DivRow) (holds : DivHolds row) :
    RemuRetiresRemainder row := by
  intro selector
  obtain ⟨unsigned, division⟩ := div_flags_remu row holds selector
  have result : divResultBytes row = row.remainder := by
    simp [divResultBytes, division]
  rw [div_destination_word row holds, result,
    remu_result_word row holds unsigned, div_source_one_word row holds,
    div_source_two_word row holds]

/-! ## Control 1 — wrong remainder sign (`REM`)

Issue #137: *delete the constraint tying the remainder's sign to the
dividend's; exhibit a signed `REM` row retiring a remainder with the wrong
sign.*

RISC-V gives the remainder the sign of the **dividend**, so `rem(-100, 7)` is
`-2` -- not `+5`, which is the Euclidean remainder, and not `+2`, which is the
remainder of the same bit pattern read as unsigned.

Two residuals carry that rule in the production AIR and only one of them can be
deleted here. The extension byte `r_hi = b_sign * (1 - r_zero) * 255` is a
*definition* (`divRemainderHigh`), not a field: it hard-wires the remainder's
sign-extension to `b_sign`, so the remainder can never carry a sign of its own.
What makes `b_sign` mean "the dividend is negative" is the `sign_range` lookup
component `2 * is_signed * (rs1_next[3] - 128 * b_sign)`, transcribed as the
field `dividendSignBit`. Delete it and `b_sign` is free on a signed row; the
prover sets it to zero, the remainder's extension byte follows it to zero, and
the entire eight-limb chain silently degenerates to the *unsigned* division of
the same bit pattern.

The row below is `REM x3, x1, x2` on `-100 / 7`. With `b_sign` released it
commits the unsigned quotient `613566742` of `0xffffff9c` by `7` and the
unsigned remainder `2`, and retires `+2` where the ISA requires `-2`
(`0xfffffffe`). Right magnitude, wrong sign — which is exactly the failure the
constraint exists to prevent, and it is invisible to every surviving residual:
the product chain balances, the comparison scan finds `7 - 2 = 5 > 0`, and the
quotient-sign lookup is satisfied because `q[3] = 0x24 < 128`.

Certifies `REM`. The deletion also bears on `DIV`, but `DivMutation.lean` has no
control for it, so this is the family's only witness that `dividendSignBit` is
load-bearing at all.
-/

structure DivHoldsWithoutDividendSignBit (row : DivRow) : Prop where
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
  -- `dividendSignBit` is deliberately absent: this is the mutation.
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
theorem divHolds_weakens_dividendSignBit
    (row : DivRow)
    (holds : DivHolds row) :
    DivHoldsWithoutDividendSignBit row where
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

/-- `REM x3, x1, x2` on `-100 / 7`, with `b_sign` released to zero. The row
reads its own dividend `0xffffff9c` as the unsigned `4294967196`, commits the
unsigned quotient `0x24924916` and the unsigned remainder `2`, and retires
`+2`. The ISA requires `-2 = 0xfffffffe`: the magnitude is right and the sign
is wrong, which is the whole content of the deleted lookup. -/
def remWrongSignRow : DivRow :=
  divWitnessRow false false true false 3 1 2
    (divBytes 156 255 255 255) (divBytes 7 0 0 0) (divBytes 22 73 146 36)
    (divBytes 2 0 0 0) (divBytes 2 0 0 0) (divBytes 2 0 0 0)
    false false false false false false
    true false false false 5 true

theorem remWrongSignRow_satisfies :
    DivHoldsWithoutDividendSignBit remWrongSignRow := by
  div_witness_holds ⟨0, 1, 3, 0, 0, 0, 0, 0, by decide⟩
    negating ⟨false, false, false, false, by decide⟩

theorem remWrongSignRow_refutes :
    ¬ RemRetiresRemainder remWrongSignRow := by
  intro claim
  exact absurd (claim (by decide)) (by decide)

/-- The published control. -/
def remWrongRemainderSign :
    MutationControl DivHoldsWithoutDividendSignBit RemRetiresRemainder where
  name := "rem-wrong-remainder-sign"
  witness := remWrongSignRow
  satisfies := remWrongSignRow_satisfies
  refutes := remWrongSignRow_refutes

/-- The deletion is not free: no strengthening of the weakened predicate back
to `DivHolds` exists, because `DivHolds` implies the architectural claim and
the witness does not satisfy it. -/
theorem rem_dividend_sign_bit_is_load_bearing :
    ¬ (∀ row, DivHoldsWithoutDividendSignBit row → DivHolds row) :=
  remWrongRemainderSign.strictly_weaker DivHolds rem_conclusion_sound

/-! ## Control 2 — released remainder bound (`REMU`)

Issue #137: *delete the comparison-scan closer `active * (1 - prefixes_0) = 0`;
exhibit a `REMU` row whose remainder is NOT smaller than the divisor.*

The deletion is `scanTotal`, the same field `DivMutation.lean` frees in its
Control 2 on a `DIVU` row, so `DivHoldsWithoutScanTotal` is reused verbatim
rather than re-transcribed. What is new is the selector the witness carries and
the conclusion it refutes, and for the remainder selectors the deletion bites
harder: `DIVU` retires the quotient, which the released bound merely shifts by
one, while `REMU` retires the very value the bound constrains.

`scanTotal` forces exactly one of the five scan participants -- `zero_divisor`,
`r_zero` and the four `lt_markers` -- to be set, which is what makes the
high-to-low scan *find* a strictly positive difference rather than merely permit
one. With it deleted the whole marker vector may be zero; the surviving
`(1 - prefixes[limb]) * diffs[limb] = 0` residuals then force every difference
to vanish, i.e. `|remainder| = |divisor|` exactly. `divisor * q + r = dividend`
still balances, because the prover simply decrements the quotient. The row below
computes `6 % 3` and retires `3`. -/

/-- `REMU x3, x1, x2` computing `6 / 3` as quotient `1` remainder `3` -- a
remainder exactly as large as the divisor, which the released scan no longer
rejects. `lt_diff` is parked at `1`, inside its `range_check_20` window, and no
`lt_markers[limb] * (lt_diff - diffs[limb])` residual is active to contradict
it. `REMU` retires the remainder, so the row commits `3` where the ISA requires
`0`. -/
def remuSlackScanRow : DivRow :=
  divWitnessRow false false false true 3 1 2
    (divBytes 6 0 0 0) (divBytes 3 0 0 0) (divBytes 1 0 0 0)
    (divBytes 3 0 0 0) (divBytes 3 0 0 0) (divBytes 3 0 0 0)
    false false false false false false
    false false false false 1 true

theorem remuSlackScanRow_satisfies :
    DivHoldsWithoutScanTotal remuSlackScanRow := by
  div_witness_holds ⟨0, 0, 0, 0, 0, 0, 0, 0, by decide⟩
    negating ⟨false, false, false, false, by decide⟩

theorem remuSlackScanRow_refutes :
    ¬ RemuRetiresRemainder remuSlackScanRow := by
  intro claim
  exact absurd (claim (by decide)) (by decide)

/-- The published control. -/
def remuReleasedRemainderBound :
    MutationControl DivHoldsWithoutScanTotal RemuRetiresRemainder where
  name := "remu-released-remainder-bound"
  witness := remuSlackScanRow
  satisfies := remuSlackScanRow_satisfies
  refutes := remuSlackScanRow_refutes

/-- The deletion is not free, and now for `REMU` specifically: `DivHolds`
implies the unsigned-remainder claim, and this witness does not satisfy it. -/
theorem remu_scan_total_is_load_bearing :
    ¬ (∀ row, DivHoldsWithoutScanTotal row → DivHolds row) :=
  remuReleasedRemainderBound.strictly_weaker DivHolds remu_conclusion_sound

/-! ## Control 3 — zero-divisor convention (`REMU`)

Issue #137: *delete the convention constraint; exhibit a divide-by-zero row
retiring something other than the dividend.*

`REM` and `REMU` by zero return the **dividend**, where `DIV` and `DIVU` return
all ones. Getting that backwards inverts the control, so it is worth being
explicit about which residual is deleted and why.

The four residuals `zero_divisor * (q[limb] - 255) = 0` commit the *quotient*
branch's convention. Deleting one of them, as `DivMutation.lean` Control 1 does,
frees a quotient byte -- and a `REMU` row does not retire the quotient, so that
deletion leaves the retired remainder architecturally correct and produces no
control for this opcode at all.

What actually carries `REMU x, 0 = x` is the product chain. Once
`zero_divisor * rs2_next[limb] = 0` has zeroed every divisor limb, the eight
`product_carries` residuals collapse to `remainder = dividend` -- that is
precisely the last conjunct of `div_zero_divisor_facts`, and it is the only
route by which `remu_result_word` reaches `Arith.remainderUnsigned_zero`. So
`productRecurrence` is the field to delete. It is one field of `DivHolds`
transcribing eight residuals, exactly as `negationRecurrence` (Control 3 of
`DivMutation.lean`) is one field transcribing twelve.

With it gone the remainder on the zero-divisor branch is completely
unconstrained: `r_zero` is forced to zero by `specialExclusive`, so the
`r_zero * r[limb] = 0` residuals are inactive; `r_sum_inv` is guarded on
`zero_divisor = 0`, so it is inactive too; and the comparison scan is closed by
`zero_divisor` itself. The row below divides `7` by zero and retires `5`.
-/

structure DivHoldsWithoutProductRecurrence (row : DivRow) : Prop where
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
  -- `productRecurrence` is deliberately absent: this is the mutation.
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
theorem divHolds_weakens_productRecurrence
    (row : DivRow)
    (holds : DivHolds row) :
    DivHoldsWithoutProductRecurrence row where
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

/-- `REMU x3, x1, x2` dividing `7` by zero. The zero-divisor branch is entered
honestly -- every divisor limb is zero, `r_zero` is off, the quotient still
carries the all-ones convention its own four residuals demand, and the
comparison scan is closed by `zero_divisor` -- but with the product chain gone
nothing forces the remainder to be the dividend, and the row retires `5` where
the ISA requires `7`. -/
def remuFreeZeroDivisorRow : DivRow :=
  divWitnessRow false false false true 3 1 2
    (divBytes 7 0 0 0) (divBytes 0 0 0 0) (divBytes 255 255 255 255)
    (divBytes 5 0 0 0) (divBytes 5 0 0 0) (divBytes 5 0 0 0)
    true false false false false false
    false false false false 0 true

theorem remuFreeZeroDivisorRow_satisfies :
    DivHoldsWithoutProductRecurrence remuFreeZeroDivisorRow := by
  div_witness_holds ⟨0, 0, 0, 0, 0, 0, 0, 0, by decide⟩
    negating ⟨false, false, false, false, by decide⟩

theorem remuFreeZeroDivisorRow_refutes :
    ¬ RemuRetiresRemainder remuFreeZeroDivisorRow := by
  intro claim
  exact absurd (claim (by decide)) (by decide)

/-- The published control. -/
def remuZeroDivisorConvention :
    MutationControl DivHoldsWithoutProductRecurrence RemuRetiresRemainder where
  name := "remu-zero-divisor-convention"
  witness := remuFreeZeroDivisorRow
  satisfies := remuFreeZeroDivisorRow_satisfies
  refutes := remuFreeZeroDivisorRow_refutes

/-- The deletion is not free: no strengthening of the weakened predicate back
to `DivHolds` exists, because `DivHolds` implies the architectural claim and
the witness does not satisfy it. -/
theorem remu_product_recurrence_is_load_bearing :
    ¬ (∀ row, DivHoldsWithoutProductRecurrence row → DivHolds row) :=
  remuZeroDivisorConvention.strictly_weaker DivHolds remu_conclusion_sound

/-! ## Control 4 — selector relabelling (`REMU` and `REM`)

Issue #137: *delete the constraint selecting `r` over `q`; exhibit a `REMU` row
retiring the quotient.*

`result[limb] = is_division * q[limb] + (1 - is_division) * r[limb]` is the only
place where the four opcode selectors reach the retired word, and the four
`destinationResultConstraints` are its limb-wise form. `DivMutation.lean`
Control 4 deletes the limb-0 member and exhibits a `DIVU` row retiring the
remainder; the two rows below run the same deletion in the opposite direction,
on the two selectors that retire `r`. `DivHoldsWithoutDestinationLimb0` is
therefore reused rather than re-transcribed.

Both directions are needed. A `DIVU` witness shows the multiplexer cannot be
released towards `r`; it says nothing about whether a remainder selector could
be released towards `q`, which is the substitution an adversarial prover would
actually want on `REM` and `REMU` -- the quotient is the larger and, on a
negative dividend, the more useful of the two committed values.
-/

/-- `REMU x3, x1, x2` computing `7 / 3 = 2` remainder `1`, honestly, and then
retiring the *quotient* `2`. The quotient and the remainder agree in limbs 1 to
3, so the three surviving destination residuals do not notice. -/
def remuRelabelledResultRow : DivRow :=
  divWitnessRow false false false true 3 1 2
    (divBytes 7 0 0 0) (divBytes 3 0 0 0) (divBytes 2 0 0 0)
    (divBytes 1 0 0 0) (divBytes 1 0 0 0) (divBytes 2 0 0 0)
    false false false false false false
    true false false false 2 true

theorem remuRelabelledResultRow_satisfies :
    DivHoldsWithoutDestinationLimb0 remuRelabelledResultRow := by
  div_witness_holds ⟨0, 0, 0, 0, 0, 0, 0, 0, by decide⟩
    negating ⟨false, false, false, false, by decide⟩

theorem remuRelabelledResultRow_refutes :
    ¬ RemuRetiresRemainder remuRelabelledResultRow := by
  intro claim
  exact absurd (claim (by decide)) (by decide)

/-- The published control. -/
def remuSelectorRelabelling :
    MutationControl DivHoldsWithoutDestinationLimb0 RemuRetiresRemainder where
  name := "remu-selector-relabelling"
  witness := remuRelabelledResultRow
  satisfies := remuRelabelledResultRow_satisfies
  refutes := remuRelabelledResultRow_refutes

/-- The deletion is not free for `REMU`. -/
theorem remu_result_selector_is_load_bearing :
    ¬ (∀ row, DivHoldsWithoutDestinationLimb0 row → DivHolds row) :=
  remuSelectorRelabelling.strictly_weaker DivHolds remu_conclusion_sound

/-- `REM x3, x1, x2` computing `(-7) / 3 = -2` remainder `-1`, honestly -- the
two's complement negation chain and the high-to-low comparison scan both run --
and then retiring the *quotient* `-2` instead of the remainder `-1`. The two
differ only in limb 0 (`0xfe` against `0xff`), so again the three surviving
destination residuals are blind to the substitution. -/
def remRelabelledResultRow : DivRow :=
  divWitnessRow false false true false 3 1 2
    (divBytes 249 255 255 255) (divBytes 3 0 0 0) (divBytes 254 255 255 255)
    (divBytes 255 255 255 255) (divBytes 1 0 0 0) (divBytes 254 255 255 255)
    false false true false true true
    true false false false 2 true

theorem remRelabelledResultRow_satisfies :
    DivHoldsWithoutDestinationLimb0 remRelabelledResultRow := by
  div_witness_holds ⟨3, 3, 3, 3, 3, 3, 3, 3, by decide⟩
    negating ⟨true, true, true, true, by decide⟩

theorem remRelabelledResultRow_refutes :
    ¬ RemRetiresRemainder remRelabelledResultRow := by
  intro claim
  exact absurd (claim (by decide)) (by decide)

/-- The published control. -/
def remSelectorRelabelling :
    MutationControl DivHoldsWithoutDestinationLimb0 RemRetiresRemainder where
  name := "rem-selector-relabelling"
  witness := remRelabelledResultRow
  satisfies := remRelabelledResultRow_satisfies
  refutes := remRelabelledResultRow_refutes

/-- The deletion is not free for `REM` either. -/
theorem rem_result_selector_is_load_bearing :
    ¬ (∀ row, DivHoldsWithoutDestinationLimb0 row → DivHolds row) :=
  remSelectorRelabelling.strictly_weaker DivHolds rem_conclusion_sound

/-! ## The architectural side of the five counterexamples -/

/-- Every counterexample above, audited against `Arith/Division.lean`. Each
pair is the value the ISA requires of the row's operands followed by the word
the witness actually retires; the two differ in all five cases. This is the
same cross-check `divMutation_architectural_answers` performs for the six
quotient-side controls, and it keeps the controls readable without unfolding a
row.

The first pair is the sign statement in full: `rem(-100, 7)` is `-2`, and the
row retires `+2`. -/
theorem remMutation_architectural_answers :
    (Arith.remainderSigned (BitVec.ofNat 32 4294967196) (BitVec.ofNat 32 7) =
          BitVec.ofNat 32 4294967294 ∧
        remWrongSignRow.rdNext.word = BitVec.ofNat 32 2) ∧
      (Arith.remainderUnsigned (BitVec.ofNat 32 6) (BitVec.ofNat 32 3) =
            zeroWord ∧
        remuSlackScanRow.rdNext.word = BitVec.ofNat 32 3) ∧
      (Arith.remainderUnsigned (BitVec.ofNat 32 7) zeroWord =
            BitVec.ofNat 32 7 ∧
        remuFreeZeroDivisorRow.rdNext.word = BitVec.ofNat 32 5) ∧
      (Arith.remainderUnsigned (BitVec.ofNat 32 7) (BitVec.ofNat 32 3) =
            BitVec.ofNat 32 1 ∧
        remuRelabelledResultRow.rdNext.word = BitVec.ofNat 32 2) ∧
      (Arith.remainderSigned (BitVec.ofNat 32 4294967289) (BitVec.ofNat 32 3) =
            BitVec.ofNat 32 4294967295 ∧
        remRelabelledResultRow.rdNext.word = BitVec.ofNat 32 4294967294) := by
  decide

/-- The remainder conventions the controls above depend on, stated directly.
`REM` and `REMU` by zero return the dividend, where `DIV` and `DIVU` return all
ones -- inverting this pair inverts Control 3. -/
theorem rem_zero_divisor_convention_is_the_dividend :
    Arith.remainderSigned (BitVec.ofNat 32 7) zeroWord = BitVec.ofNat 32 7 ∧
      Arith.remainderUnsigned (BitVec.ofNat 32 7) zeroWord =
        BitVec.ofNat 32 7 ∧
      Arith.divideSigned (BitVec.ofNat 32 7) zeroWord = Arith.allOnesWord ∧
      Arith.divideUnsigned (BitVec.ofNat 32 7) zeroWord = Arith.allOnesWord := by
  decide

/-- The sign rule, stated on the operands of Control 1: RISC-V takes the sign of
the dividend, so `rem(-100, 7) = -2`. The Euclidean answer `+5` and the
unsigned answer `+2` are both wrong, and the witness commits the latter. -/
theorem rem_takes_the_sign_of_the_dividend :
    Arith.remainderSigned (BitVec.ofNat 32 4294967196) (BitVec.ofNat 32 7) =
        BitVec.ofNat 32 4294967294 ∧
      Arith.signedValue (BitVec.ofNat 32 4294967196) = -100 ∧
      Arith.signedValue (BitVec.ofNat 32 4294967294) = -2 ∧
      Arith.remainderUnsigned (BitVec.ofNat 32 4294967196)
          (BitVec.ofNat 32 7) = BitVec.ofNat 32 2 := by
  decide

/-! ## Non-vacuity of the two new weakened predicates

`divHolds_weakens_dividendSignBit` and `divHolds_weakens_productRecurrence`
already show every honest row survives each deletion. These restate that on
concrete rows, so neither weakened predicate is a claim about something nothing
satisfies. -/

theorem divHoldsWithoutDividendSignBit_nonvacuous :
    DivHoldsWithoutDividendSignBit divWitnessNegativeRemainder :=
  divHolds_weakens_dividendSignBit _ divWitnessNegativeRemainder_holds

theorem divHoldsWithoutProductRecurrence_nonvacuous :
    DivHoldsWithoutProductRecurrence divWitnessZeroDivisor :=
  divHolds_weakens_productRecurrence _ divWitnessZeroDivisor_holds

/-! ## Each mutation is real

`MutationControl.witness_not_sound` already proves each witness is outside
`DivHolds`, and each `..._satisfies` proof shows every *retained* field holds on
it, so the field that fails can only be the deleted one. The statements below
pin that down directly: they exhibit the deleted residual failing on its own
witness, so no control here is an accident of a row that happens to break some
other constraint.

The first four are decidable residuals. The fifth is the product chain, whose
limb-0 member would need `5 = 7 + 256 * k` on a row whose divisor is zero and
whose remainder is `5` -- unsatisfiable for every carry. -/

theorem remWrongSignRow_violates_dividendSignBit :
    ¬ (remWrongSignRow.isSigned = true →
        remWrongSignRow.bSign =
          decide (128 ≤ remWrongSignRow.rs1Next.limb3.toNat)) := by
  decide

theorem remuSlackScanRow_violates_scanTotal :
    remuSlackScanRow.zeroDivisor.toNat + remuSlackScanRow.rZero.toNat +
        remuSlackScanRow.ltMarker3.toNat + remuSlackScanRow.ltMarker2.toNat +
        remuSlackScanRow.ltMarker1.toNat + remuSlackScanRow.ltMarker0.toNat
      ≠ 1 := by
  decide

theorem remuRelabelledResultRow_violates_destinationLimb0 :
    remuRelabelledResultRow.rdNext.limb0 ≠
      (if remuRelabelledResultRow.destinationNonzero then
          (divResultBytes remuRelabelledResultRow).limb0
        else 0) := by
  decide

theorem remRelabelledResultRow_violates_destinationLimb0 :
    remRelabelledResultRow.rdNext.limb0 ≠
      (if remRelabelledResultRow.destinationNonzero then
          (divResultBytes remRelabelledResultRow).limb0
        else 0) := by
  decide

theorem remuFreeZeroDivisorRow_violates_productRecurrence (k0 : Nat) :
    divConv0 remuFreeZeroDivisorRow ≠
      remuFreeZeroDivisorRow.rs1Next.limb0.toNat + 256 * k0 := by
  intro identity
  rw [show divConv0 remuFreeZeroDivisorRow = 5 from by decide,
    show remuFreeZeroDivisorRow.rs1Next.limb0.toNat = 7 from by decide]
    at identity
  omega

/-! ## No witness is an honest row

Restating the deletions as the `Mutation.lean` sanity check: each witness is
provably outside the *unweakened* row predicate, so none of the five controls
was manufactured by weakening a constraint that never mattered. -/

theorem remMutation_witnesses_are_not_sound :
    ¬ DivHolds remWrongSignRow ∧
      ¬ DivHolds remuSlackScanRow ∧
      ¬ DivHolds remuFreeZeroDivisorRow ∧
      ¬ DivHolds remuRelabelledResultRow ∧
      ¬ DivHolds remRelabelledResultRow :=
  ⟨remWrongRemainderSign.witness_not_sound DivHolds rem_conclusion_sound,
    remuReleasedRemainderBound.witness_not_sound DivHolds remu_conclusion_sound,
    remuZeroDivisorConvention.witness_not_sound DivHolds remu_conclusion_sound,
    remuSelectorRelabelling.witness_not_sound DivHolds remu_conclusion_sound,
    remSelectorRelabelling.witness_not_sound DivHolds rem_conclusion_sound⟩

/-! ## Coverage claim

Together with `Opcodes/DivMutation.lean` every member of the DIV family now
carries at least one mutation control whose witness row sets that member's own
selector:

  * `DIV`  -- `divFreeRemainderMagnitude` (`is_div`).
  * `DIVU` -- five controls (`is_divu`).
  * `REM`  -- `remWrongRemainderSign` and `remSelectorRelabelling` (`is_rem`).
  * `REMU` -- `remuReleasedRemainderBound`, `remuZeroDivisorConvention` and
    `remuSelectorRelabelling` (`is_remu`).

No control below claims credit for an opcode on the strength of a sibling's
witness. -/

theorem remMutation_selectors_are_carried :
    remWrongSignRow.isRem = true ∧
      remRelabelledResultRow.isRem = true ∧
      remuSlackScanRow.isRemu = true ∧
      remuFreeZeroDivisorRow.isRemu = true ∧
      remuRelabelledResultRow.isRemu = true := by
  decide

end RiscvRefinement.Opcodes
