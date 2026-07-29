-- REVIEWED NORMALIZED CAPSULE. This file is *not* a generated-Sail theorem.
--
-- The pinned Sail theorem backend is not available in this environment (no
-- Sail compiler is installed here), so the architectural side of the DIV
-- family below is a hand-written normalized capsule. It is the same epistemic
-- *class* as RiscvRefinement/Sail/Generated/Pilot.lean -- a reviewed capsule,
-- not a generated-Sail theorem -- but not the same status: Pilot.lean is
-- generator output pinned to SHA-256 digests of real generated Sail text,
-- while this file is hand-written, with no generator, no digest, and no
-- derivation from any Sail artifact. Replacing this capsule with a
-- generated definition slice extracted from the pinned Sail model, together
-- with its translation receipt, is the open obligation for this family.
--
-- Reviewed against the RISC-V unprivileged specification, "M" standard
-- extension, integer division instructions:
--   * DIV  rd, rs1, rs2  -- signed quotient, truncated toward zero
--   * DIVU rd, rs1, rs2  -- unsigned quotient
--   * REM  rd, rs1, rs2  -- signed remainder, sign of the dividend
--   * REMU rd, rs1, rs2  -- unsigned remainder
-- Division by zero does not trap: DIV and DIVU return all ones, REM and REMU
-- return the dividend. Signed overflow (INT_MIN / -1) does not trap either:
-- DIV returns INT_MIN and REM returns zero. Both conventions are proved as
-- characterization lemmas in RiscvRefinement/Arith/Division.lean.
--
-- None of these instructions touches memory and all of them retire at pc + 4.

import RiscvRefinement.Arith.Division

namespace RiscvRefinement.Sail.Reviewed

open RiscvRefinement
open RiscvRefinement.Arith

/-- Review tag for the capsule below. It is deliberately not a definition
digest of a generated Sail slice, because no such slice exists here. -/
def divReviewedCapsuleTag : String :=
  "riscv-m-integer-division-reviewed-capsule"

/-- `DIV`. -/
def executeDivValue (dividend divisor : Word) : Word :=
  divideSigned dividend divisor

/-- `DIVU`. -/
def executeDivuValue (dividend divisor : Word) : Word :=
  divideUnsigned dividend divisor

/-- `REM`. -/
def executeRemValue (dividend divisor : Word) : Word :=
  remainderSigned dividend divisor

/-- `REMU`. -/
def executeRemuValue (dividend divisor : Word) : Word :=
  remainderUnsigned dividend divisor

/-- The shared retirement shape of the whole family: advance the program
counter by four, write one register, touch no memory. -/
def executeDivision (pc : Word) (rd : RegisterIndex) (value : Word) :
    Retirement where
  nextPc := nextPc pc
  write := architecturalWrite rd value
  read := none
  store := none

def executeDiv (pc : Word) (rd : RegisterIndex) (dividend divisor : Word) :
    Retirement :=
  executeDivision pc rd (executeDivValue dividend divisor)

def executeDivu (pc : Word) (rd : RegisterIndex) (dividend divisor : Word) :
    Retirement :=
  executeDivision pc rd (executeDivuValue dividend divisor)

def executeRem (pc : Word) (rd : RegisterIndex) (dividend divisor : Word) :
    Retirement :=
  executeDivision pc rd (executeRemValue dividend divisor)

def executeRemu (pc : Word) (rd : RegisterIndex) (dividend divisor : Word) :
    Retirement :=
  executeDivision pc rd (executeRemuValue dividend divisor)

/-! ## The reviewed conventions, restated on the capsule -/

theorem executeDiv_zero_divisor (pc : Word) (rd : RegisterIndex)
    (dividend : Word) :
    executeDiv pc rd dividend zeroWord =
      executeDivision pc rd allOnesWord := by
  simp [executeDiv, executeDivValue, divideSigned_zero]

theorem executeDivu_zero_divisor (pc : Word) (rd : RegisterIndex)
    (dividend : Word) :
    executeDivu pc rd dividend zeroWord =
      executeDivision pc rd allOnesWord := by
  simp [executeDivu, executeDivuValue, divideUnsigned_zero]

theorem executeRem_zero_divisor (pc : Word) (rd : RegisterIndex)
    (dividend : Word) :
    executeRem pc rd dividend zeroWord = executeDivision pc rd dividend := by
  simp [executeRem, executeRemValue, remainderSigned_zero]

theorem executeRemu_zero_divisor (pc : Word) (rd : RegisterIndex)
    (dividend : Word) :
    executeRemu pc rd dividend zeroWord = executeDivision pc rd dividend := by
  simp [executeRemu, executeRemuValue, remainderUnsigned_zero]

theorem executeDiv_overflow (pc : Word) (rd : RegisterIndex) :
    executeDiv pc rd intMinWord minusOneWord =
      executeDivision pc rd intMinWord := by
  simp [executeDiv, executeDivValue, divideSigned_overflow]

theorem executeRem_overflow (pc : Word) (rd : RegisterIndex) :
    executeRem pc rd intMinWord minusOneWord =
      executeDivision pc rd zeroWord := by
  simp [executeRem, executeRemValue, remainderSigned_overflow]

/-- No member of the family has a memory effect. -/
theorem executeDivision_no_memory (pc : Word) (rd : RegisterIndex)
    (value : Word) :
    (executeDivision pc rd value).read = none ∧
      (executeDivision pc rd value).store = none :=
  ⟨rfl, rfl⟩

theorem executeDivision_next_pc (pc : Word) (rd : RegisterIndex)
    (value : Word) :
    (executeDivision pc rd value).nextPc = nextPc pc := rfl

end RiscvRefinement.Sail.Reviewed
