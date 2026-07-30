-- Refinement of the production DIV/DIVU/REM/REMU AIR against the reviewed
-- normalized architectural capsule.
--
-- The architectural side is RiscvRefinement/Sail/Reviewed/Div.lean, a reviewed
-- normalized capsule and not a generated-Sail theorem; replacing it with a
-- generated definition slice is the open obligation. The AIR side is the exact
-- transcription in RiscvRefinement/Air/Family/Div.lean of the exported
-- production symbolic IR (sha256
-- 430a06a8919e469251deab180b492e89a4a6452de0014b2b0c3ea6c350912e4d).
--
-- Every destination word below is derived from the row's byte-limb product
-- recurrence, sign lookups and comparison witnesses. No theorem here consumes
-- a hypothesis stating that the committed quotient or remainder is already
-- architecturally correct.

import RiscvRefinement.Air.Family.Div
import RiscvRefinement.Sail.Reviewed.Div

namespace RiscvRefinement.Opcodes

open RiscvRefinement
open RiscvRefinement.Air.Family
open RiscvRefinement.Sail.Reviewed

/-- The binding between a committed row and the architectural pre-state. -/
structure DivEnvironment (row : DivRow) where
  pre : PreState
  pcBinds : row.pc = pre.pc
  dividendBinds : row.rs1Previous.word = pre.registers row.rs1
  divisorBinds : row.rs2Previous.word = pre.registers row.rs2
  destinationBinds : row.rdPrevious.word = pre.registers row.rd

/-- The complete refinement obligation for one DIV-family row: the normalized
retirement, the absence of any memory effect, and every relation tuple the row
places on the program, state and register buses. -/
structure DivRefinement
    (row : DivRow)
    (environment : DivEnvironment row)
    (opcodeId : Nat)
    (result : Word) :
    Prop where
  retirement :
    divRetirement row = executeDivision environment.pre.pc row.rd result
  nextPcResult : (divRetirement row).nextPc = nextPc environment.pre.pc
  noRead : (divRetirement row).read = none
  noStore : (divRetirement row).store = none
  programTuple :
    (divRelations row).program = {
      pc := environment.pre.pc
      opcodeId := opcodeId
      rd := row.rd.toNat
      rs1 := row.rs1.toNat
      operand := row.rs2.toNat
    }
  stateConsume :
    (divRelations row).stateConsume = {
      pc := environment.pre.pc
      clock := row.clock
    }
  stateEmit :
    (divRelations row).stateEmit = {
      pc := nextPc environment.pre.pc
      clock := row.clock + 1
    }
  sourceOneConsume :
    (divRelations row).sourceOneConsume = {
      addr := row.rs1
      clock := row.rs1PreviousClock
      value := environment.pre.registers row.rs1
    }
  sourceOneEmit :
    (divRelations row).sourceOneEmit = {
      addr := row.rs1
      clock := accessClock row.clock 1
      value := environment.pre.registers row.rs1
    }
  sourceTwoConsume :
    (divRelations row).sourceTwoConsume = {
      addr := row.rs2
      clock := row.rs2PreviousClock
      value := environment.pre.registers row.rs2
    }
  sourceTwoEmit :
    (divRelations row).sourceTwoEmit = {
      addr := row.rs2
      clock := accessClock row.clock 2
      value := environment.pre.registers row.rs2
    }
  destinationConsume :
    (divRelations row).destinationConsume = {
      addr := row.rd
      clock := row.rdPreviousClock
      value := environment.pre.registers row.rd
    }
  destinationEmit :
    (divRelations row).destinationEmit = {
      addr := row.rd
      clock := accessClock row.clock 3
      value := architecturalValue row.rd result
    }

/-- The read-only residuals identify the limbs the semantics compute on with
the architectural pre-state registers. -/
theorem div_operands
    (row : DivRow)
    (environment : DivEnvironment row)
    (holds : DivHolds row) :
    row.rs1Next.word = environment.pre.registers row.rs1 ∧
      row.rs2Next.word = environment.pre.registers row.rs2 :=
  ⟨(div_source_one_word row holds).trans environment.dividendBinds,
    (div_source_two_word row holds).trans environment.divisorBinds⟩

/-- The selector-independent half of the refinement. -/
theorem div_family_refines
    (row : DivRow)
    (environment : DivEnvironment row)
    (holds : DivHolds row)
    (opcodeId : Nat)
    (result : Word)
    (opcodeIdEq : divOpcodeId row = opcodeId)
    (resultEq : (divResultBytes row).word = result) :
    DivRefinement row environment opcodeId result := by
  have destination :
      row.rdNext.word = architecturalValue row.rd result := by
    rw [div_destination_word row holds, resultEq]
  constructor
  · unfold divRetirement executeDivision
    rw [holds.nextPcResult, environment.pcBinds, destination,
      architecturalWrite_value]
  · show row.claimedNextPc = nextPc environment.pre.pc
    rw [holds.nextPcResult, environment.pcBinds]
  · rfl
  · rfl
  · simp [divRelations, divProgramTuple, environment.pcBinds, opcodeIdEq]
  · simp [divRelations, environment.pcBinds]
  · simp [divRelations, environment.pcBinds]
  · simp [divRelations, environment.dividendBinds]
  · simp [divRelations, (div_operands row environment holds).1]
  · simp [divRelations, environment.divisorBinds]
  · simp [divRelations, (div_operands row environment holds).2]
  · simp [divRelations, environment.destinationBinds]
  · simp [divRelations, destination]

/-! ## The four selectors -/

theorem div_refines
    (row : DivRow)
    (environment : DivEnvironment row)
    (holds : DivHolds row)
    (selector : row.isDiv = true) :
    DivRefinement row environment 41
      (executeDivValue
        (environment.pre.registers row.rs1)
        (environment.pre.registers row.rs2)) := by
  obtain ⟨signed, division⟩ := div_flags_div row holds selector
  obtain ⟨dividend, divisor⟩ := div_operands row environment holds
  refine div_family_refines row environment holds 41 _
    (div_opcode_id_div row holds selector) ?_
  · show (divResultBytes row).word = _
    rw [show divResultBytes row = row.quotient by simp [divResultBytes, division],
      div_result_word row holds signed, dividend, divisor]
    rfl

theorem divu_refines
    (row : DivRow)
    (environment : DivEnvironment row)
    (holds : DivHolds row)
    (selector : row.isDivu = true) :
    DivRefinement row environment 42
      (executeDivuValue
        (environment.pre.registers row.rs1)
        (environment.pre.registers row.rs2)) := by
  obtain ⟨unsigned, division⟩ := div_flags_divu row holds selector
  obtain ⟨dividend, divisor⟩ := div_operands row environment holds
  refine div_family_refines row environment holds 42 _
    (div_opcode_id_divu row holds selector) ?_
  · show (divResultBytes row).word = _
    rw [show divResultBytes row = row.quotient by simp [divResultBytes, division],
      divu_result_word row holds unsigned, dividend, divisor]
    rfl

theorem rem_refines
    (row : DivRow)
    (environment : DivEnvironment row)
    (holds : DivHolds row)
    (selector : row.isRem = true) :
    DivRefinement row environment 43
      (executeRemValue
        (environment.pre.registers row.rs1)
        (environment.pre.registers row.rs2)) := by
  obtain ⟨signed, division⟩ := div_flags_rem row holds selector
  obtain ⟨dividend, divisor⟩ := div_operands row environment holds
  refine div_family_refines row environment holds 43 _
    (div_opcode_id_rem row holds selector) ?_
  · show (divResultBytes row).word = _
    rw [show divResultBytes row = row.remainder by
        simp [divResultBytes, division],
      rem_result_word row holds signed, dividend, divisor]
    rfl

theorem remu_refines
    (row : DivRow)
    (environment : DivEnvironment row)
    (holds : DivHolds row)
    (selector : row.isRemu = true) :
    DivRefinement row environment 44
      (executeRemuValue
        (environment.pre.registers row.rs1)
        (environment.pre.registers row.rs2)) := by
  obtain ⟨unsigned, division⟩ := div_flags_remu row holds selector
  obtain ⟨dividend, divisor⟩ := div_operands row environment holds
  refine div_family_refines row environment holds 44 _
    (div_opcode_id_remu row holds selector) ?_
  · show (divResultBytes row).word = _
    rw [show divResultBytes row = row.remainder by
        simp [divResultBytes, division],
      remu_result_word row holds unsigned, dividend, divisor]
    rfl

/-! ## Retirement against the reviewed capsule -/

theorem div_retires_as_reviewed
    (row : DivRow)
    (environment : DivEnvironment row)
    (holds : DivHolds row)
    (selector : row.isDiv = true) :
    divRetirement row =
      executeDiv environment.pre.pc row.rd
        (environment.pre.registers row.rs1)
        (environment.pre.registers row.rs2) :=
  (div_refines row environment holds selector).retirement

theorem divu_retires_as_reviewed
    (row : DivRow)
    (environment : DivEnvironment row)
    (holds : DivHolds row)
    (selector : row.isDivu = true) :
    divRetirement row =
      executeDivu environment.pre.pc row.rd
        (environment.pre.registers row.rs1)
        (environment.pre.registers row.rs2) :=
  (divu_refines row environment holds selector).retirement

theorem rem_retires_as_reviewed
    (row : DivRow)
    (environment : DivEnvironment row)
    (holds : DivHolds row)
    (selector : row.isRem = true) :
    divRetirement row =
      executeRem environment.pre.pc row.rd
        (environment.pre.registers row.rs1)
        (environment.pre.registers row.rs2) :=
  (rem_refines row environment holds selector).retirement

theorem remu_retires_as_reviewed
    (row : DivRow)
    (environment : DivEnvironment row)
    (holds : DivHolds row)
    (selector : row.isRemu = true) :
    divRetirement row =
      executeRemu environment.pre.pc row.rd
        (environment.pre.registers row.rs1)
        (environment.pre.registers row.rs2) :=
  (remu_refines row environment holds selector).retirement

/-! ## Non-vacuity witnesses

Every theorem above is conditional on `DivHolds`. The rows below are concrete
models of that predicate, so none of those theorems is vacuously true, and
together they cover the branches the constraint system distinguishes. -/

def divBytes (limb0 limb1 limb2 limb3 : Nat) : WordBytes where
  limb0 := BitVec.ofNat 8 limb0
  limb1 := BitVec.ofNat 8 limb1
  limb2 := BitVec.ofNat 8 limb2
  limb3 := BitVec.ofNat 8 limb3

/-- A committed row at pc `0x1000` and clock `9`, with both source accesses
read-only and the three access-chain clocks at their production ordinals. -/
def divWitnessRow
    (isDiv isDivu isRem isRemu : Bool)
    (rd rs1 rs2 : Nat)
    (dividend divisor quotient remainder remainderAbs destination : WordBytes)
    (zeroDivisor rZero bSign cSign qSign signXor : Bool)
    (ltMarker0 ltMarker1 ltMarker2 ltMarker3 : Bool)
    (ltDiff : Nat)
    (destinationNonzero : Bool) :
    DivRow where
  pc := BitVec.ofNat 32 4096
  clock := 9
  rd := BitVec.ofNat 5 rd
  rdPreviousClock := 0
  rdPrevious := WordBytes.zero
  rdNext := destination
  rs1 := BitVec.ofNat 5 rs1
  rs1PreviousClock := 0
  rs1Previous := dividend
  rs1Next := dividend
  rs2 := BitVec.ofNat 5 rs2
  rs2PreviousClock := 0
  rs2Previous := divisor
  rs2Next := divisor
  zeroDivisor := zeroDivisor
  rZero := rZero
  quotient := quotient
  remainder := remainder
  bSign := bSign
  cSign := cSign
  qSign := qSign
  signXor := signXor
  remainderAbs := remainderAbs
  ltMarker0 := ltMarker0
  ltMarker1 := ltMarker1
  ltMarker2 := ltMarker2
  ltMarker3 := ltMarker3
  ltDiff := ltDiff
  isDiv := isDiv
  isDivu := isDivu
  isRem := isRem
  isRemu := isRemu
  destinationNonzero := destinationNonzero
  claimedNextPc := nextPc (BitVec.ofNat 32 4096)

/-- `DIVU x3, x1, x2` with a zero divisor: the quotient is all ones and the
remainder is the dividend. -/
def divWitnessZeroDivisor : DivRow :=
  divWitnessRow false true false false 3 1 2
    (divBytes 7 0 0 0) (divBytes 0 0 0 0) (divBytes 255 255 255 255)
    (divBytes 7 0 0 0) (divBytes 7 0 0 0) (divBytes 255 255 255 255)
    true false false false false false
    false false false false 0 true

/-- Discharge every field of `DivHolds` for a concrete row: `decide` for the
decidable residuals, the supplied product carries for the eight-limb
recurrence, and the supplied negation carries for the two's complement chain
(which is vacuous whenever `sign_xor = 0`). -/
macro "div_witness_holds" carries:term "negating" negation:term : tactic =>
  `(tactic|
    (constructor
     all_goals
       first
         | decide
         | exact ⟨by decide, by decide⟩
         | exact $carries
         | exact fun _ => $negation
         | simp))

theorem divWitnessZeroDivisor_holds : DivHolds divWitnessZeroDivisor := by
  div_witness_holds ⟨0, 0, 0, 0, 0, 0, 0, 0, by decide⟩
    negating ⟨false, false, false, false, by decide⟩

theorem divWitnessZeroDivisor_quotient :
    (divResultBytes divWitnessZeroDivisor).word = Arith.allOnesWord := by
  decide

/-- `DIV x1, x1, x2` at the signed overflow point `INT_MIN / -1`. The AIR
represents the architectural result `INT_MIN` with `q_sign = sign_xor = 0`, so
this row exercises the both-negative class the quotient-sign lookup skips. -/
def divWitnessOverflow : DivRow :=
  divWitnessRow true false false false 1 1 2
    (divBytes 0 0 0 128) (divBytes 255 255 255 255) (divBytes 0 0 0 128)
    (divBytes 0 0 0 0) (divBytes 0 0 0 0) (divBytes 0 0 0 128)
    false true true true false false
    false false false false 0 true

theorem divWitnessOverflow_holds : DivHolds divWitnessOverflow := by
  div_witness_holds ⟨0, 0, 0, 127, 127, 127, 127, 127, by decide⟩
    negating ⟨false, false, false, false, by decide⟩

theorem divWitnessOverflow_quotient :
    (divResultBytes divWitnessOverflow).word = Arith.intMinWord := by
  decide

/-- `REM` at the same overflow point yields zero. -/
def divWitnessOverflowRemainder : DivRow :=
  divWitnessRow false false true false 1 1 2
    (divBytes 0 0 0 128) (divBytes 255 255 255 255) (divBytes 0 0 0 128)
    (divBytes 0 0 0 0) (divBytes 0 0 0 0) (divBytes 0 0 0 0)
    false true true true false false
    false false false false 0 true

theorem divWitnessOverflowRemainder_holds :
    DivHolds divWitnessOverflowRemainder := by
  div_witness_holds ⟨0, 0, 0, 127, 127, 127, 127, 127, by decide⟩
    negating ⟨false, false, false, false, by decide⟩

theorem divWitnessOverflowRemainder_result :
    (divResultBytes divWitnessOverflowRemainder).word = zeroWord := by
  decide

/-- `DIV x1, x1, x2` computing `(-7) / 3 = -2` with remainder `-1`: a signed
negative remainder, so `sign_xor = 1` and the two's complement negation chain
and the high-to-low comparison scan both run. -/
def divWitnessNegativeRemainder : DivRow :=
  divWitnessRow true false false false 1 1 2
    (divBytes 249 255 255 255) (divBytes 3 0 0 0) (divBytes 254 255 255 255)
    (divBytes 255 255 255 255) (divBytes 1 0 0 0) (divBytes 254 255 255 255)
    false false true false true true
    true false false false 2 true

theorem divWitnessNegativeRemainder_holds :
    DivHolds divWitnessNegativeRemainder := by
  div_witness_holds ⟨3, 3, 3, 3, 3, 3, 3, 3, by decide⟩
    negating ⟨true, true, true, true, by decide⟩

theorem divWitnessNegativeRemainder_quotient :
    (divResultBytes divWitnessNegativeRemainder).word =
      BitVec.ofNat 32 4294967294 := by
  decide

/-- `DIVU x5, x1, x2` on `0x8abcdef1 / 1`: the dividend has bit 31 set, so the
unsigned quotient is the dividend itself and the row must not activate the
quotient-sign lookup. -/
def divWitnessHighBitUnsigned : DivRow :=
  divWitnessRow false true false false 5 1 2
    (divBytes 241 222 188 138) (divBytes 1 0 0 0) (divBytes 241 222 188 138)
    (divBytes 0 0 0 0) (divBytes 0 0 0 0) (divBytes 241 222 188 138)
    false true false false false false
    false false false false 0 true

theorem divWitnessHighBitUnsigned_holds :
    DivHolds divWitnessHighBitUnsigned := by
  div_witness_holds ⟨0, 0, 0, 0, 0, 0, 0, 0, by decide⟩
    negating ⟨false, false, false, false, by decide⟩

theorem divWitnessHighBitUnsigned_quotient :
    (divResultBytes divWitnessHighBitUnsigned).word =
      BitVec.ofNat 32 0x8abcdef1 := by
  decide

/-- `DIVU x3, x2, x2`: both source operands are the same architectural
register, so the read-only residuals and the two register access chains have to
agree on one address. -/
def divWitnessAliasedOperands : DivRow :=
  divWitnessRow false true false false 3 2 2
    (divBytes 5 0 0 0) (divBytes 5 0 0 0) (divBytes 1 0 0 0)
    (divBytes 0 0 0 0) (divBytes 0 0 0 0) (divBytes 1 0 0 0)
    false true false false false false
    false false false false 0 true

theorem divWitnessAliasedOperands_holds :
    DivHolds divWitnessAliasedOperands := by
  div_witness_holds ⟨0, 0, 0, 0, 0, 0, 0, 0, by decide⟩
    negating ⟨false, false, false, false, by decide⟩

theorem divWitnessAliasedOperands_sources :
    divWitnessAliasedOperands.rs1 = divWitnessAliasedOperands.rs2 := by decide

/-- `DIVU x0, x1, x2` on `7 / 3`: the destination is `x0`, so the write-enable
witness is zero and the emitted destination limbs must all vanish even though
the computed quotient is two. -/
def divWitnessZeroDestination : DivRow :=
  divWitnessRow false true false false 0 1 2
    (divBytes 7 0 0 0) (divBytes 3 0 0 0) (divBytes 2 0 0 0)
    (divBytes 1 0 0 0) (divBytes 1 0 0 0) (divBytes 0 0 0 0)
    false false false false false false
    true false false false 2 false

theorem divWitnessZeroDestination_holds :
    DivHolds divWitnessZeroDestination := by
  div_witness_holds ⟨0, 0, 0, 0, 0, 0, 0, 0, by decide⟩
    negating ⟨false, false, false, false, by decide⟩

theorem divWitnessZeroDestination_writes_nothing :
    (divRetirement divWitnessZeroDestination).write = none := by decide

theorem divWitnessZeroDestination_quotient :
    (divResultBytes divWitnessZeroDestination).word = BitVec.ofNat 32 2 := by
  decide

/-- Cross-check against the architectural specification. Each conjunct is the
value the corresponding witness row commits, computed independently from
`Arith/Division.lean`. Together with the `DivHolds` proofs above this shows the
witnesses are models of the intended instructions and not merely of the
constraint system. -/
theorem divWitness_architectural_agreement :
    Arith.divideUnsigned (BitVec.ofNat 32 7) zeroWord = Arith.allOnesWord ∧
      Arith.divideSigned Arith.intMinWord Arith.minusOneWord =
        Arith.intMinWord ∧
      Arith.remainderSigned Arith.intMinWord Arith.minusOneWord = zeroWord ∧
      Arith.divideSigned (BitVec.ofNat 32 4294967289) (BitVec.ofNat 32 3) =
        BitVec.ofNat 32 4294967294 ∧
      Arith.remainderSigned (BitVec.ofNat 32 4294967289) (BitVec.ofNat 32 3) =
        BitVec.ofNat 32 4294967295 ∧
      Arith.divideUnsigned (BitVec.ofNat 32 0x8abcdef1) (BitVec.ofNat 32 1) =
        BitVec.ofNat 32 0x8abcdef1 ∧
      Arith.divideUnsigned (BitVec.ofNat 32 5) (BitVec.ofNat 32 5) =
        BitVec.ofNat 32 1 ∧
      Arith.divideUnsigned (BitVec.ofNat 32 7) (BitVec.ofNat 32 3) =
        BitVec.ofNat 32 2 := by
  decide

/-- No witness row claims a memory effect. -/
theorem divWitness_no_memory :
    (divRetirement divWitnessZeroDivisor).read = none ∧
      (divRetirement divWitnessZeroDivisor).store = none ∧
      (divRetirement divWitnessNegativeRemainder).read = none ∧
      (divRetirement divWitnessNegativeRemainder).store = none :=
  ⟨rfl, rfl, rfl, rfl⟩

end RiscvRefinement.Opcodes
