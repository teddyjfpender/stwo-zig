-- REVIEWED NORMALIZED CAPSULE. This is *not* a generated-Sail theorem file.
--
-- The generated pinned-Sail theorem backend is unavailable in this
-- environment (no Sail compiler is installed), so the architectural side of
-- the RV32M multiply refinements is a hand-written normalized capsule of the
-- pinned model's `MUL` execute clause. It is the same epistemic *class* as
-- RiscvRefinement/Sail/Generated/Pilot.lean -- a reviewed capsule, explicitly
-- not a generated-Sail theorem -- but not the same status: Pilot.lean is
-- generator output pinned to SHA-256 digests of real generated Sail text,
-- while this file is hand-written, with no generator, no digest, and no
-- derivation from any Sail artifact. Replacing it with a generated-Sail
-- definition slice is the open obligation; until that happens no claim in
-- this development is publication-level for the architectural side.
--
-- Reviewed source, at the pinned sail-riscv revision
-- 8c7f2da58de0ba5e4457e4de07e0046f0439f35f (the layout `sail.py` pins via
-- `model/riscv.sail_project`; the path `riscv_insts_mext.sail` cited by an
-- earlier revision of this header does not exist in that layout):
--
--   `model/extensions/M/mext_insts.sail`, the execute clause:
--
--     function clause execute MUL(rs2, rs1, rd, mul_op) = {
--       let rs1_bits = X(rs1);
--       let rs2_bits = X(rs2);
--       X(rd) = mult_to_bits_half(xlen, mul_op.signed_rs1, mul_op.signed_rs2,
--                                 rs1_bits, rs2_bits, mul_op.result_part);
--       RETIRE_SUCCESS
--     }
--
--   `model/core/arithmetic.sail`, the helper it calls:
--
--     function mult_to_bits_half(l, sign1, sign2, rs1_bits, rs2_bits, result_part) = {
--       let rs1_int : int = match sign1 {
--         Signed   => signed(rs1_bits),
--         Unsigned => unsigned(rs1_bits),
--       };
--       let rs2_int : int = match sign2 {
--         Signed   => signed(rs2_bits),
--         Unsigned => unsigned(rs2_bits),
--       };
--       let result_wide = to_bits_truncate(2 * l, rs1_int * rs2_int);
--       match result_part {
--         High => result_wide[(2 * l - 1) .. l],
--         Low  => result_wide[(l - 1) .. 0],
--       }
--     }
--
--   `model/extensions/M/mext_types.sail` defines the `mul_op` struct
--   (`result_part`, `signed_rs1`, `signed_rs2`), and the `encdec_mul_op`
--   mapping in `mext_insts.sail` fixes the four selectors:
--   `mul = {Low, Signed, Signed}`, `mulh = {High, Signed, Signed}`,
--   `mulhsu = {High, Signed, Unsigned}`, `mulhu = {High, Unsigned, Unsigned}`.
--
-- The quotations above are themselves a hand transcription from the pinned
-- revision, checked by eye and not by digest: unlike Pilot.lean, nothing pins
-- them mechanically.
--
-- Normalization: with `xlen = 32`, `to_bits_truncate(64, n)` is the
-- two's-complement 64-bit encoding of `n`, i.e. `n` reduced modulo `2 ^ 64`;
-- that is exactly `BitVec 64` multiplication of the extended operands, which
-- is how the four selectors below are normalized.

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
