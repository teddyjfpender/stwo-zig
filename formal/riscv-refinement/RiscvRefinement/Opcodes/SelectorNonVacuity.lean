-- Per-selector non-vacuity witnesses.
--
-- Issue #137 asks for an honest non-vacuity theorem *per opcode*: a theorem
-- whose statement names the selector, exhibits a concrete row satisfying the
-- constraint system, exhibits a binding to an architectural pre-state, and
-- carries the full refinement conclusion for that selector.
--
-- The DIV-family witnesses in `RiscvRefinement/Opcodes/Div.lean` are named
-- after the *case* they exercise (`divWitnessOverflow`, ...), not after the
-- selector, and three of them (`divWitnessOverflow`,
-- `divWitnessOverflowRemainder`, `divWitnessNegativeRemainder`) commit
-- `rd = rs1 = x1` with `rdPrevious = 0` while `rs1Previous = dividend ≠ 0`.
-- No `DivEnvironment` can exist for such a row: `dividendBinds` and
-- `destinationBinds` would force `pre.registers x1` to be two different words.
-- There is also no `REMU` witness anywhere in the tree. The rows below
-- therefore re-derive the same four architectural cases with `rd` distinct
-- from `rs1`, which is what makes a full `DivRefinement` statable.
--
-- The shift witnesses in `RiscvRefinement/Opcodes/Shifts.lean` do carry
-- environments, but none of `slli_exists`, `srli_exists`, `srai_exists`,
-- `sll_exists`, `srl_exists`, `sra_exists` states which `ShiftKind` the row
-- commits, so the same reviewer objection applies. The theorems below restate
-- them with the selector named and with the decode fact that pins the encoded
-- opcode. The one existing witness that is degenerate is `srliWitnessRow`:
-- its shift amount is `0`, so its movement equations are the identity and it
-- exercises no byte or bit motion at all. It is not wrapped here; a fresh
-- `SRLI` witness at shift amount 8 is built instead.

import RiscvRefinement.Opcodes.Div
import RiscvRefinement.Opcodes.Shifts

namespace RiscvRefinement.Opcodes.SelectorNonVacuity

open RiscvRefinement
open RiscvRefinement.Air.Family
open RiscvRefinement.Sail.Reviewed

/-! ## DIV family

Each row below is `divWitnessRow` at a destination register distinct from both
sources, so the three `DivEnvironment` binding fields are simultaneously
satisfiable. The arithmetic of each row is the arithmetic of the correspondingly
named witness in `Opcodes/Div.lean`; only the destination register index and the
selector flags differ, and neither participates in the product recurrence. -/

/-- Pre-state for a `DIV`-family witness: `x1` holds the dividend, `x2` the
divisor, and the destination `x3` starts at zero. -/
def divPre (dividend divisor : Word) : PreState where
  pc := BitVec.ofNat 32 4096
  registers := fun index =>
    if index = BitVec.ofNat 5 1 then dividend
    else if index = BitVec.ofNat 5 2 then divisor
    else zeroWord
  x0IsZero := by simp [zeroRegister]

/-! ### DIV: the signed overflow point `INT_MIN / -1` -/

/-- `DIV x3, x1, x2` with `x1 = INT_MIN` and `x2 = -1`. Both operand sign bits
are set, which is the class the quotient-sign lookup skips, and the
architectural quotient `INT_MIN` is the one value whose sign the committed
`q_sign = 0` cannot be read off. -/
def divOverflowRow : DivRow :=
  divWitnessRow true false false false 3 1 2
    (divBytes 0 0 0 128) (divBytes 255 255 255 255) (divBytes 0 0 0 128)
    (divBytes 0 0 0 0) (divBytes 0 0 0 0) (divBytes 0 0 0 128)
    false true true true false false
    false false false false 0 true

theorem divOverflowRow_holds : DivHolds divOverflowRow := by
  constructor
  all_goals
    first
      | decide
      | exact ⟨by decide, by decide⟩
      | exact ⟨0, 0, 0, 127, 127, 127, 127, 127, by decide⟩
      | exact fun _ => ⟨false, false, false, false, by decide⟩
      | simp

def divOverflowEnvironment : DivEnvironment divOverflowRow where
  pre := divPre Arith.intMinWord Arith.minusOneWord
  pcBinds := rfl
  dividendBinds := by decide
  divisorBinds := by decide
  destinationBinds := by decide

/-- `DIV` is inhabited: there is a row that satisfies every DIV-family
constraint, whose `is_div` selector is set, whose operands are the signed
overflow pair, and which refines the architectural `DIV` at opcode id 41. -/
theorem div_exists :
    ∃ (row : DivRow) (environment : DivEnvironment row),
      DivHolds row ∧
        row.isDiv = true ∧
        environment.pre.registers row.rs1 = Arith.intMinWord ∧
        environment.pre.registers row.rs2 = Arith.minusOneWord ∧
        (divResultBytes row).word = Arith.intMinWord ∧
        DivRefinement row environment 41
          (executeDivValue
            (environment.pre.registers row.rs1)
            (environment.pre.registers row.rs2)) :=
  ⟨divOverflowRow, divOverflowEnvironment, divOverflowRow_holds, rfl,
    by decide, by decide, by decide,
    div_refines divOverflowRow divOverflowEnvironment divOverflowRow_holds rfl⟩

/-! ### DIVU: a dividend with bit 31 set

This reuses `divWitnessHighBitUnsigned` unchanged — its destination `x5` is
already distinct from both sources, so an environment exists for it. -/

def divuHighBitEnvironment : DivEnvironment divWitnessHighBitUnsigned where
  pre := divPre (BitVec.ofNat 32 0x8abcdef1) (BitVec.ofNat 32 1)
  pcBinds := rfl
  dividendBinds := by decide
  divisorBinds := by decide
  destinationBinds := by decide

/-- `DIVU` is inhabited. The dividend's top bit is set and yet the row commits
`b_sign = 0`: on an unsigned row bit 31 is magnitude, not sign, so the quotient
`0x8abcdef1` is above `2 ^ 31` and no sign-extension byte is engaged. -/
theorem divu_exists :
    ∃ (row : DivRow) (environment : DivEnvironment row),
      DivHolds row ∧
        row.isDivu = true ∧
        row.rs1Next.word.msb = true ∧
        row.bSign = false ∧
        (divResultBytes row).word = BitVec.ofNat 32 0x8abcdef1 ∧
        DivRefinement row environment 42
          (executeDivuValue
            (environment.pre.registers row.rs1)
            (environment.pre.registers row.rs2)) :=
  ⟨divWitnessHighBitUnsigned, divuHighBitEnvironment,
    divWitnessHighBitUnsigned_holds, rfl, by decide, rfl, by decide,
    divu_refines divWitnessHighBitUnsigned divuHighBitEnvironment
      divWitnessHighBitUnsigned_holds rfl⟩

/-! ### REM: a negative remainder -/

/-- `REM x3, x1, x2` computing `(-7) % 3 = -1`. The dividend is negative and
the divisor is positive, so `sign_xor = 1`: the two's complement negation chain
that produces `|r|` runs, and the high-to-low magnitude scan compares `1 < 3`
at limb 0. The committed result is negative, which the unsigned family could
never produce for these magnitudes. -/
def remNegativeRow : DivRow :=
  divWitnessRow false false true false 3 1 2
    (divBytes 249 255 255 255) (divBytes 3 0 0 0) (divBytes 254 255 255 255)
    (divBytes 255 255 255 255) (divBytes 1 0 0 0) (divBytes 255 255 255 255)
    false false true false true true
    true false false false 2 true

theorem remNegativeRow_holds : DivHolds remNegativeRow := by
  constructor
  all_goals
    first
      | decide
      | exact ⟨by decide, by decide⟩
      | exact ⟨3, 3, 3, 3, 3, 3, 3, 3, by decide⟩
      | exact fun _ => ⟨true, true, true, true, by decide⟩
      | simp

def remNegativeEnvironment : DivEnvironment remNegativeRow where
  pre := divPre (BitVec.ofNat 32 4294967289) (BitVec.ofNat 32 3)
  pcBinds := rfl
  dividendBinds := by decide
  divisorBinds := by decide
  destinationBinds := by decide

/-- `REM` is inhabited, with a genuinely negative remainder. -/
theorem rem_exists :
    ∃ (row : DivRow) (environment : DivEnvironment row),
      DivHolds row ∧
        row.isRem = true ∧
        row.signXor = true ∧
        (divResultBytes row).word.msb = true ∧
        (divResultBytes row).word = BitVec.ofNat 32 4294967295 ∧
        DivRefinement row environment 43
          (executeRemValue
            (environment.pre.registers row.rs1)
            (environment.pre.registers row.rs2)) :=
  ⟨remNegativeRow, remNegativeEnvironment, remNegativeRow_holds, rfl, rfl,
    by decide, by decide,
    rem_refines remNegativeRow remNegativeEnvironment remNegativeRow_holds rfl⟩

/-! ### REMU: the divisor-zero convention -/

/-- `REMU x3, x1, x2` with `x2 = 0`. RISC-V defines the remainder by zero to be
the dividend, and the AIR reaches it through the `zero_divisor` branch, which
simultaneously forces the (unused) quotient to all ones. -/
def remuZeroDivisorRow : DivRow :=
  divWitnessRow false false false true 3 1 2
    (divBytes 7 0 0 0) (divBytes 0 0 0 0) (divBytes 255 255 255 255)
    (divBytes 7 0 0 0) (divBytes 7 0 0 0) (divBytes 7 0 0 0)
    true false false false false false
    false false false false 0 true

theorem remuZeroDivisorRow_holds : DivHolds remuZeroDivisorRow := by
  constructor
  all_goals
    first
      | decide
      | exact ⟨by decide, by decide⟩
      | exact ⟨0, 0, 0, 0, 0, 0, 0, 0, by decide⟩
      | exact fun _ => ⟨false, false, false, false, by decide⟩
      | simp

def remuZeroDivisorEnvironment : DivEnvironment remuZeroDivisorRow where
  pre := divPre (BitVec.ofNat 32 7) zeroWord
  pcBinds := rfl
  dividendBinds := by decide
  divisorBinds := by decide
  destinationBinds := by decide

/-- `REMU` is inhabited, and its witness pins the divisor-zero convention: the
divisor really is zero and the committed result really is the dividend. -/
theorem remu_exists :
    ∃ (row : DivRow) (environment : DivEnvironment row),
      DivHolds row ∧
        row.isRemu = true ∧
        row.zeroDivisor = true ∧
        environment.pre.registers row.rs2 = zeroWord ∧
        (divResultBytes row).word = environment.pre.registers row.rs1 ∧
        DivRefinement row environment 44
          (executeRemuValue
            (environment.pre.registers row.rs1)
            (environment.pre.registers row.rs2)) :=
  ⟨remuZeroDivisorRow, remuZeroDivisorEnvironment, remuZeroDivisorRow_holds,
    rfl, rfl, by decide, by decide,
    remu_refines remuZeroDivisorRow remuZeroDivisorEnvironment
      remuZeroDivisorRow_holds rfl⟩

/-- The four rows above agree with `Arith/Division.lean` on the architectural
value each one claims, so they are models of the intended instructions and not
merely of the constraint system. -/
theorem divFamily_architectural_agreement :
    Arith.divideSigned Arith.intMinWord Arith.minusOneWord =
        Arith.intMinWord ∧
      Arith.divideUnsigned (BitVec.ofNat 32 0x8abcdef1) (BitVec.ofNat 32 1) =
        BitVec.ofNat 32 0x8abcdef1 ∧
      Arith.remainderSigned (BitVec.ofNat 32 4294967289) (BitVec.ofNat 32 3) =
        BitVec.ofNat 32 4294967295 ∧
      Arith.remainderUnsigned (BitVec.ofNat 32 7) zeroWord =
        BitVec.ofNat 32 7 := by
  decide

/-- None of the four rows is degenerate: every destination is a writable
register, so each one really does exercise the architectural write path. -/
theorem divFamily_destinations_are_writable :
    divOverflowRow.rd ≠ zeroRegister ∧
      divWitnessHighBitUnsigned.rd ≠ zeroRegister ∧
      remNegativeRow.rd ≠ zeroRegister ∧
      remuZeroDivisorRow.rd ≠ zeroRegister := by
  refine ⟨?_, ?_, ?_, ?_⟩ <;> decide

/-! ## Shift family

The six witnesses of `Opcodes/Shifts.lean` are reused unchanged except for
`SRLI`, whose existing witness shifts by zero and therefore exercises no
movement. Each theorem below names the `ShiftKind` selector and carries the
decode fact that pins the encoded opcode, so none of them can be satisfied by a
row of a different shift. -/

/-! ### SLLI -/

theorem slli_selector_exists :
    ∃ (row : ShiftsImmRow) (environment : ShiftsImmEnvironment row),
      ShiftsImmHolds row ∧
        row.semantic.kind = ShiftKind.sll ∧
        Decode.isSlli environment.word = true ∧
        row.semantic.shiftAmount = 31 ∧
        row.semantic.result.word = BitVec.ofNat 32 0x80000000 ∧
        ShiftsImmRefinement row environment :=
  let facts :=
    slli_refines slliWitnessRow slliWitnessEnvironment slli_witness_holds rfl
  ⟨slliWitnessRow, slliWitnessEnvironment, slli_witness_holds, rfl,
    facts.2.1, by decide, by decide, facts.1⟩

/-! ### SRLI

`srliWitnessRow` in `Opcodes/Shifts.lean` commits `shiftAmount = 0`: its
movement equations degenerate to `result = source` and no byte or bit actually
moves. It is deliberately not reused here. The row below shifts `0x12345678`
right by eight, which moves one whole limb and zero-fills the top. -/

def srliShiftPre : PreState where
  pc := BitVec.ofNat 32 0x1000
  registers := fun index =>
    if index = BitVec.ofNat 5 5 then BitVec.ofNat 32 0x12345678 else zeroWord
  x0IsZero := by decide

def srliShiftSemantic : ShiftRow where
  rs1Previous := shiftBytes 0x78 0x56 0x34 0x12
  rs1Next := shiftBytes 0x78 0x56 0x34 0x12
  rs1Sign := false
  kind := ShiftKind.srl
  limbIndex := 1
  bitIndex := 0
  carry0 := 0
  carry1 := 0
  carry2 := 0
  carry3 := 0
  result := shiftBytes 0x56 0x34 0x12 0x00
  rd := BitVec.ofNat 5 7
  rdPrevious := WordBytes.zero
  rdNext := shiftBytes 0x56 0x34 0x12 0x00
  rdNonzero := true

def srliShiftRow : ShiftsImmRow where
  pc := BitVec.ofNat 32 0x1000
  clock := 1
  rs1 := BitVec.ofNat 5 5
  rs1PreviousClock := 0
  rdPreviousClock := 0
  immTruncated := 8
  semantic := srliShiftSemantic
  claimedNextPc := nextPc (BitVec.ofNat 32 0x1000)

theorem srliShiftRow_holds : ShiftsImmHolds srliShiftRow := by
  refine {
    core := ?_
    clockPositive := by decide
    sourceClock := ?_
    destinationClock := ?_
    immediateBinds := rfl
    nextPcResult := rfl
  }
  · refine {
      limbIndexRange := by decide
      bitIndexRange := by decide
      signIsLogicalZero := fun _ => rfl
      signLowerBound := fun h => absurd h (by decide)
      signUpperBound := fun h => absurd h (by decide)
      carry0Range := by decide
      carry1Range := by decide
      carry2Range := by decide
      carry3Range := by decide
      sourceReadOnly := rfl
      leftMovement := fun h => absurd h (by decide)
      rightMovement := ?_
      destinationFlag := by decide
      destinationLimb0 := by decide
      destinationLimb1 := by decide
      destinationLimb2 := by decide
      destinationLimb3 := by decide
    }
    intro _
    refine ⟨?_, ?_, ?_, ?_⟩ <;> decide
  · simp [validPreviousClock, accessClock, srliShiftRow]
  · simp [validPreviousClock, accessClock, srliShiftRow]

def srliShiftEnvironment : ShiftsImmEnvironment srliShiftRow where
  pre := srliShiftPre
  word := shiftsImmEncoding srliShiftRow
  pcBinds := rfl
  wordBinds := rfl
  sourceBinds := by decide
  destinationBinds := by decide

theorem srli_selector_exists :
    ∃ (row : ShiftsImmRow) (environment : ShiftsImmEnvironment row),
      ShiftsImmHolds row ∧
        row.semantic.kind = ShiftKind.srl ∧
        Decode.isSrli environment.word = true ∧
        row.semantic.shiftAmount = 8 ∧
        row.semantic.rs1Next.word = BitVec.ofNat 32 0x12345678 ∧
        row.semantic.result.word = BitVec.ofNat 32 0x00123456 ∧
        ShiftsImmRefinement row environment :=
  let facts :=
    srli_refines srliShiftRow srliShiftEnvironment srliShiftRow_holds rfl
  ⟨srliShiftRow, srliShiftEnvironment, srliShiftRow_holds, rfl,
    facts.2.1, by decide, by decide, by decide, facts.1⟩

/-! ### SRAI -/

theorem srai_selector_exists :
    ∃ (row : ShiftsImmRow) (environment : ShiftsImmEnvironment row),
      ShiftsImmHolds row ∧
        row.semantic.kind = ShiftKind.sra ∧
        Decode.isSrai environment.word = true ∧
        row.semantic.rs1Sign = true ∧
        row.semantic.shiftAmount = 8 ∧
        row.semantic.result.word = BitVec.ofNat 32 0xff800000 ∧
        row.semantic.result.word ≠
          row.semantic.rs1Next.word >>> row.semantic.shiftAmount ∧
        ShiftsImmRefinement row environment :=
  let facts :=
    srai_refines sraiWitnessRow sraiWitnessEnvironment srai_witness_holds rfl
  ⟨sraiWitnessRow, sraiWitnessEnvironment, srai_witness_holds, rfl,
    facts.2.1, rfl, by decide, by decide, by decide, facts.1⟩

/-! ### SLL -/

theorem sll_selector_exists :
    ∃ (row : ShiftsRegRow) (environment : ShiftsRegEnvironment row),
      ShiftsRegHolds row ∧
        row.semantic.kind = ShiftKind.sll ∧
        Decode.isSll environment.word = true ∧
        row.semantic.rd = row.rs1 ∧
        row.semantic.shiftAmount = 1 ∧
        row.semantic.result.word = BitVec.ofNat 32 0x22 ∧
        ShiftsRegRefinement row environment :=
  let facts :=
    sll_refines sllWitnessRow sllWitnessEnvironment sll_witness_holds rfl
  ⟨sllWitnessRow, sllWitnessEnvironment, sll_witness_holds, rfl,
    facts.2.1, rfl, by decide, by decide, facts.1⟩

/-! ### SRL -/

theorem srl_selector_exists :
    ∃ (row : ShiftsRegRow) (environment : ShiftsRegEnvironment row),
      ShiftsRegHolds row ∧
        row.semantic.kind = ShiftKind.srl ∧
        Decode.isSrl environment.word = true ∧
        row.semantic.shiftAmount = 31 ∧
        row.semantic.result.word = BitVec.ofNat 32 1 ∧
        ShiftsRegRefinement row environment :=
  let facts :=
    srl_refines srlWitnessRow srlWitnessEnvironment srl_witness_holds rfl
  ⟨srlWitnessRow, srlWitnessEnvironment, srl_witness_holds, rfl,
    facts.2.1, by decide, by decide, facts.1⟩

/-! ### SRA -/

theorem sra_selector_exists :
    ∃ (row : ShiftsRegRow) (environment : ShiftsRegEnvironment row),
      ShiftsRegHolds row ∧
        row.semantic.kind = ShiftKind.sra ∧
        Decode.isSra environment.word = true ∧
        row.rs2Next.word.toNat = 255 ∧
        row.semantic.shiftAmount = 31 ∧
        row.semantic.rs1Sign = true ∧
        row.semantic.result.word = BitVec.ofNat 32 0xffffffff ∧
        ShiftsRegRefinement row environment :=
  let facts :=
    sra_refines sraWitnessRow sraWitnessEnvironment sra_witness_holds rfl
  ⟨sraWitnessRow, sraWitnessEnvironment, sra_witness_holds, rfl,
    facts.2.1, by decide, by decide, rfl, by decide, facts.1⟩

/-- No shift witness cited above is degenerate: each commits a nonzero shift
amount, so each really exercises byte or bit movement. -/
theorem shift_witnesses_move :
    slliWitnessRow.semantic.shiftAmount ≠ 0 ∧
      srliShiftRow.semantic.shiftAmount ≠ 0 ∧
      sraiWitnessRow.semantic.shiftAmount ≠ 0 ∧
      sllWitnessRow.semantic.shiftAmount ≠ 0 ∧
      srlWitnessRow.semantic.shiftAmount ≠ 0 ∧
      sraWitnessRow.semantic.shiftAmount ≠ 0 := by
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_⟩ <;> decide

end RiscvRefinement.Opcodes.SelectorNonVacuity
