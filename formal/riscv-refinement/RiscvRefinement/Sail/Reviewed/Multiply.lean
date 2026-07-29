-- REVIEWED NORMALIZED CAPSULE. This is *not* a generated-Sail theorem file.
--
-- The generated pinned-Sail theorem backend is unavailable in this
-- environment (no Sail compiler is installed), so the architectural side of
-- the RV32M multiply refinements is a hand-reviewed normalized capsule of the
-- `MUL` clause of `riscv_insts_mext.sail`, in exactly the same status as
-- RiscvRefinement/Sail/Generated/Pilot.lean. Replacing this file with a
-- generated-Sail definition slice is the open obligation; until that happens
-- no claim in this development is publication-level for the architectural
-- side.
--
-- Reviewed source clause (RV32, `xlen = 32`):
--
--   function clause execute (MUL(rs2, rs1, rd, high, signed1, signed2)) = {
--     let rs1_val = X(rs1);
--     let rs2_val = X(rs2);
--     let rs1_int : int = if signed1 then signed(rs1_val) else unsigned(rs1_val);
--     let rs2_int : int = if signed2 then signed(rs2_val) else unsigned(rs2_val);
--     let result_wide = to_bits(2 * sizeof(xlen), rs1_int * rs2_int);
--     let result = if high
--                  then result_wide[(2 * sizeof(xlen) - 1) .. sizeof(xlen)]
--                  else result_wide[(sizeof(xlen) - 1) .. 0];
--     X(rd) = result
--   }
--
-- `to_bits(64, n)` is the two's-complement 64-bit encoding of `n`, i.e. `n`
-- reduced modulo `2 ^ 64`; that is exactly `BitVec 64` multiplication of the
-- extended operands, which is how the four selectors below are normalized.
-- `(high, signed1, signed2)` is `(false, true, true)` for `MUL`,
-- `(true, true, true)` for `MULH`, `(true, true, false)` for `MULHSU` and
-- `(true, false, false)` for `MULHU`.

import RiscvRefinement.Common

namespace RiscvRefinement.Sail.Reviewed

open RiscvRefinement

/-- `MUL`: the low slice of the 64-bit product of the two signed operands. -/
def executeMulValue (source1 source2 : Word) : Word :=
  BitVec.setWidth 32
    (BitVec.signExtend 64 source1 * BitVec.signExtend 64 source2)

/-- `MULH`: the high slice of the 64-bit signed x signed product. -/
def executeMulhValue (source1 source2 : Word) : Word :=
  BitVec.setWidth 32
    ((BitVec.signExtend 64 source1 * BitVec.signExtend 64 source2) >>> 32)

/-- `MULHSU`: the high slice of the 64-bit signed x unsigned product. -/
def executeMulhsuValue (source1 source2 : Word) : Word :=
  BitVec.setWidth 32
    ((BitVec.signExtend 64 source1 * BitVec.setWidth 64 source2) >>> 32)

/-- `MULHU`: the high slice of the 64-bit unsigned x unsigned product. -/
def executeMulhuValue (source1 source2 : Word) : Word :=
  BitVec.setWidth 32
    ((BitVec.setWidth 64 source1 * BitVec.setWidth 64 source2) >>> 32)

/-- The normalization the capsule relies on for the low slice: bits 31..0 of
the 64-bit product do not depend on how the operands were extended, so the
`MUL` value is plain 32-bit multiplication. Proved, not assumed. -/
theorem executeMulValue_eq_mul (source1 source2 : Word) :
    executeMulValue source1 source2 = source1 * source2 := by
  rw [executeMulValue, BitVec.setWidth_mul _ _ (by omega)]
  congr 1
  · bv_decide
  · bv_decide

def executeMul
    (pc : Word)
    (source1 source2 : Word)
    (rd : RegisterIndex) :
    Retirement where
  nextPc := nextPc pc
  write := architecturalWrite rd (executeMulValue source1 source2)

def executeMulh
    (pc : Word)
    (source1 source2 : Word)
    (rd : RegisterIndex) :
    Retirement where
  nextPc := nextPc pc
  write := architecturalWrite rd (executeMulhValue source1 source2)

def executeMulhsu
    (pc : Word)
    (source1 source2 : Word)
    (rd : RegisterIndex) :
    Retirement where
  nextPc := nextPc pc
  write := architecturalWrite rd (executeMulhsuValue source1 source2)

def executeMulhu
    (pc : Word)
    (source1 source2 : Word)
    (rd : RegisterIndex) :
    Retirement where
  nextPc := nextPc pc
  write := architecturalWrite rd (executeMulhuValue source1 source2)

/-- None of the four selectors touches memory: the reviewed clause writes only
`X(rd)` and advances the program counter. -/
theorem executeMul_no_memory
    (pc source1 source2 : Word)
    (rd : RegisterIndex) :
    (executeMul pc source1 source2 rd).read = none ∧
      (executeMul pc source1 source2 rd).store = none := ⟨rfl, rfl⟩

theorem executeMulh_no_memory
    (pc source1 source2 : Word)
    (rd : RegisterIndex) :
    (executeMulh pc source1 source2 rd).read = none ∧
      (executeMulh pc source1 source2 rd).store = none := ⟨rfl, rfl⟩

theorem executeMulhsu_no_memory
    (pc source1 source2 : Word)
    (rd : RegisterIndex) :
    (executeMulhsu pc source1 source2 rd).read = none ∧
      (executeMulhsu pc source1 source2 rd).store = none := ⟨rfl, rfl⟩

theorem executeMulhu_no_memory
    (pc source1 source2 : Word)
    (rd : RegisterIndex) :
    (executeMulhu pc source1 source2 rd).read = none ∧
      (executeMulhu pc source1 source2 rd).store = none := ⟨rfl, rfl⟩

end RiscvRefinement.Sail.Reviewed
