-- The AIR-interpreter bridge for the `load_store` family: `LB`, `LH`, `LW`,
-- `LBU`, `LHU`, `SB`, `SH`, `SW`.
--
-- Third family bridged this way, after `Air/Bridge/MulBridge.lean` (22 roots)
-- and `Air/Bridge/MulhBridge.lean` (30 roots). Issue #137 forbids Team B from
-- restating production constraints in a private Lean predicate, and
-- `RiscvRefinement/Air/Family/LoadStore.lean` currently does exactly that:
-- `LoadStoreHolds` is a hand transcription of `/tmp/tb-ir/load_store.json`.
-- This file maps a typed `LoadStoreRow` onto the 48 columns of the shipped AIR
-- and proves, by *evaluating the encoded production node table*, that whenever
-- `LoadStoreHolds row` holds
--
--   * every one of the 63 constraint roots evaluates to zero,
--   * every live fixed-table request lands inside its table, and
--   * every one of the 16 lookup tuples is the transcribed relation tuple.
--
-- So the hand transcription is not weaker than the shipped AIR: nothing the
-- AIR asks for on a placed row is missing from it.
--
-- Three things are new relative to the two multiply families.
--
-- 1. **An eight-way selector.** `mul` has a committed `enabler` pinned to one
--    and `mulh` a three-way selector; `load_store`'s "enabler" is the sum of
--    eight opcode flags, pinned to one by root 69. Every derived gate the AIR
--    uses -- `opcode_b`, `opcode_h`, `load_b`, `load_h`, `is_signed`,
--    `is_store`, `is_load` -- is a *field sum* of those flags, and the
--    transcription spells the same gates as *boolean disjunctions*. The two
--    agree only because at most one flag is set, so the eight-way case split
--    is discharged once, in `selectorCases`, and reused by the seven image
--    lemmas below rather than repeated at each of the 78 roots.
--
-- 2. **Memory lookups.** This is the first bridged family whose
--    `memory_access` requests carry an address space that is not the constant
--    `0`: lookups 8/9 carry `is_load` and lookups 11/12 carry `is_store`, so a
--    load's `src` block is data memory (space 1) and a store's `src` block is
--    the `rs2` register (space 0), with `dst` the other way round. The same
--    swap moves the access-clock ordinals: the memory side always sits at
--    ordinal three and the register side at ordinal two, which the AIR spells
--    as the single node `4*(clk-1) + 2 + is_load` (resp. `+ is_store`).
--
-- 3. **Alignment is a lookup, not an equation.** Nothing in the constraint
--    roots forces the effective address to be word-aligned. The only thing
--    that does is lookup 6, the `range_check_20` request on
--    `(src_addr_selector + dst_addr_selector - r2_idx) / 4`; the division is
--    multiplication by `4⁻¹ = 536870912` in `M31`, so a request that lands in
--    the table certifies both `aligned_addr ≡ 0 (mod 4)` and
--    `aligned_addr < 2^22`. `loadStoreFixedRequestsHold` is therefore
--    load-bearing for this family in exactly the way `mulFixedRequestsHold` is
--    for the multiply families' product identity: a bridge scoped to the
--    constraint roots would certify a `load_store` AIR with no alignment
--    discipline at all. See issue #140 and /tmp/o4-ls-bridge-report.md.
--
-- The pc-wrap side condition `LoadStoreRowFits` is carried forward from the
-- `mul` bridge for the same reason (see the docstring on it): `LoadStoreRow.pc`
-- is a `BitVec 32` whose `nextPc` wraps, and the AIR's `pc` is a field element
-- whose next-pc node is `pc + 4`. `LoadStoreHolds` does not imply the two
-- agree.
--
-- What is NOT proved here is the list in /tmp/o1-bridge-report.md section 3,
-- plus the `load_store`-specific items in /tmp/o4-ls-bridge-report.md.

import RiscvRefinement.Air.Bridge.LoadStoreProgram
import RiscvRefinement.Air.Bridge.MulBridge
import RiscvRefinement.Air.Family.LoadStore

namespace RiscvRefinement.Air.Bridge

open RiscvRefinement
open RiscvRefinement.Air.Family

set_option maxRecDepth 20000

-- The eight-way selector is discharged by rewriting with all eight flag
-- equations at once; which of them a given image lemma actually needs varies
-- by branch, and listing only the used ones would make the eight branches
-- textually different for no gain.
set_option linter.unusedSimpArgs false

-- The generated evaluator and the hand transcription are pinned independently.
-- `loadStoreProgramIrDigest` is the canonical content digest of the selector
-- AIR IR v2 input. `loadStoreIrDigest` is the byte digest of the aggregate
-- typed-family export checked by `riscv_team_b.py`; that compatibility export
-- additionally materialises eight derived bus values, so the serialisations
-- are not byte-identical. The polynomial digest is independently checked by
-- `riscv_air_ir_equivalence.py` against the reviewed pre-cutover family export.
#guard loadStoreProgramIrDigest ==
  "129cebd7398199ce1422ebc94585919ee162b86280d16993ad4b0b0e1e2c1e80"
#guard loadStoreIrDigest ==
  "44b8ffa7d86cfff1b914e8dfde132284d356e976a6fe4a90d8b62252a1c21ea9"
#guard loadStorePolynomialDigest ==
  "d19899f907d0d5a3ec364963e1f3901e03c2620e3ad203a01bbf2e298775b59f"

/-! ## The `M31` arithmetic this family adds

Everything else comes from `MulBridge.lean`, whose `M31` layer is
family-independent. `load_store` needs two more exact-division facts: the AIR
divides by four (the aligned-address quarter, and the half-word placement
gates) and by two (the half-word shift amount), and both are spelled as
multiplication by the corresponding inverse in `M31`. -/

namespace M31

/-- `4 * 536870912 = 2 ^ 31 = modulus + 1`, so the AIR's multiplication by
`536870912` really is division by four. -/
theorem reduce_quarter (value : Nat) :
    M31.reduce (4 * value * 536870912) = M31.reduce value := by
  apply eq_of_val
  simp only [val_reduce]
  have expand : 4 * value * 536870912 = value + modulus * value := by
    simp only [modulus, m31Modulus]
    omega
  rw [expand, Nat.add_mul_mod_self_left]

/-- `2 * 1073741824 = 2 ^ 31 = modulus + 1`, so the AIR's multiplication by
`1073741824` really is division by two. -/
theorem reduce_half (value : Nat) :
    M31.reduce (2 * value * 1073741824) = M31.reduce value := by
  apply eq_of_val
  simp only [val_reduce]
  have expand : 2 * value * 1073741824 = value + modulus * value := by
    simp only [modulus, m31Modulus]
    omega
  rw [expand, Nat.add_mul_mod_self_left]

/-- `x - x = 0` for an arbitrary field element, not only for an image of
`reduce`. Several `load_store` roots subtract two *derived* expressions. -/
theorem sub_cancel (value : M31) : value - value = 0 := by
  apply eq_of_val
  simp only [val_sub, val_zero]
  rw [show value.val + modulus - value.val = modulus from by omega, Nat.mod_self]

theorem add_zero (value : M31) : value + 0 = value := by
  apply eq_of_val
  simp only [val_add, val_zero, Nat.add_zero]
  exact Nat.mod_eq_of_lt value.isLt

theorem zero_add (value : M31) : 0 + value = value := by
  apply eq_of_val
  simp only [val_add, val_zero, Nat.zero_add]
  exact Nat.mod_eq_of_lt value.isLt

theorem sub_zero (value : M31) : value - 0 = value := by
  apply eq_of_val
  simp only [val_sub, val_zero, Nat.sub_zero]
  rw [Nat.add_mod_right]
  exact Nat.mod_eq_of_lt value.isLt

theorem one_mul (value : M31) : M31.reduce 1 * value = value := by
  apply eq_of_val
  simp only [val_mul, val_reduce]
  rw [show (1 : Nat) % modulus = 1 from by decide, Nat.one_mul]
  exact Nat.mod_eq_of_lt value.isLt

end M31

/-- `(M31.reduce v).toNat < b` whenever `v < b`; the bound survives reduction
because `v % p ≤ v`. -/
private theorem reduceToNat_lt {value bound : Nat} (small : value < bound) :
    (M31.reduce value).toNat < bound := by
  simp only [M31.toNat, M31.val_reduce]
  exact Nat.lt_of_le_of_lt (Nat.mod_le _ _) small

/-- A gated constraint whose gate is off. -/
private theorem mulLeftZero {left right : M31} (zero : left = 0) :
    left * right = 0 := by
  rw [zero]
  exact M31.zero_mul right

/-- A gated constraint whose gated body is zero. -/
private theorem mulRightZero {left right : M31} (zero : right = 0) :
    left * right = 0 := by
  rw [zero]
  exact M31.mul_zero left

/-- The four `is_lw / is_sw` roots are a *sum* of two gated terms. -/
private theorem addZeros {left right : M31} (leftZero : left = 0)
    (rightZero : right = 0) : left + right = 0 := by
  rw [leftZero, rightZero]
  exact M31.add_zero 0

/-- A difference of two equal reductions. -/
private theorem subZero {left right : M31} (equal : left = right) :
    left - right = 0 := by
  rw [equal]
  exact M31.sub_cancel right

/-- The `x * (x - 1) = 0` residual of a column carrying a boolean. -/
private theorem bitBooleanVanishes (flag : Bool) :
    M31.reduce (bitValue flag) *
        (M31.reduce (bitValue flag) - M31.reduce 1) = 0 := by
  cases flag with
  | false => exact mulLeftZero rfl
  | true => exact mulRightZero (M31.sub_self 1)

/-! ## The access clocks of the two swapping blocks

`load_store` commits two access blocks, `src` and `dst`, and which of them is
the memory side depends on the direction. The AIR writes the two emitted
clocks as `4*(clk-1) + 2 + is_load` and `4*(clk-1) + 2 + is_store`, which is
ordinal three for whichever block is memory and ordinal two for whichever is a
register. -/

/-- The access clock the `src` block emits, exactly as the AIR spells it. -/
def sourceAccessClock (row : LoadStoreRow) : Nat :=
  accessClock row.clock 2 + bitValue row.isLoad

/-- The access clock the `dst` block emits, exactly as the AIR spells it. -/
def destinationAccessClock (row : LoadStoreRow) : Nat :=
  accessClock row.clock 2 + bitValue row.isStore

/-- On a load the `src` block is memory, so it sits at ordinal three. -/
theorem sourceAccessClock_load (row : LoadStoreRow) (direction : row.isStore = false) :
    sourceAccessClock row = accessClock row.clock 3 := by
  simp only [sourceAccessClock, LoadStoreRow.isLoad, direction, Bool.not_false,
    bitValue_true, accessClock]

/-- On a store the `src` block is the `rs2` register, so it sits at ordinal
two. -/
theorem sourceAccessClock_store (row : LoadStoreRow) (direction : row.isStore = true) :
    sourceAccessClock row = accessClock row.clock 2 := by
  simp only [sourceAccessClock, LoadStoreRow.isLoad, direction, Bool.not_true,
    bitValue_false, Nat.add_zero]

/-- On a load the `dst` block is the `rd` register, so it sits at ordinal
two. -/
theorem destinationAccessClock_load (row : LoadStoreRow)
    (direction : row.isStore = false) :
    destinationAccessClock row = accessClock row.clock 2 := by
  simp only [destinationAccessClock, direction, bitValue_false, Nat.add_zero]

/-- On a store the `dst` block is memory, so it sits at ordinal three. -/
theorem destinationAccessClock_store (row : LoadStoreRow)
    (direction : row.isStore = true) :
    destinationAccessClock row = accessClock row.clock 3 := by
  simp only [destinationAccessClock, direction, bitValue_true, accessClock]

/-! ## The column assignment

`LoadStoreRow` is not a complete AIR row. Three groups of columns have no
counterpart in the transcription and are synthesised here:

* `dst_addr` (column 2) and `src_addr` (column 18) are **dead** in the shipped
  AIR — no node reads either of them, which the generated file records — so
  they are assigned zero. The live addresses are `src_addr_selector` and
  `dst_addr_selector`, columns 28 and 29, and those are the derived selectors
  `LoadStoreRow.sourceSelector` / `destinationSelector` that C16 and C17 define.
* `destination_inverse` (column 47) is the `M31` inverse of `r2_idx`, taken
  from the same 32-entry table `MulBridge.lean` uses.
The source access values are each represented once; their emitted lookup tuples
reuse the consumed limbs directly. Derived bus values remain expression nodes
and no longer occupy committed trace columns. -/

/-- The typed row, laid out as the 48 columns of `load_store.json`. -/
def loadStoreColumns (row : LoadStoreRow) : List M31 :=
  [ M31.reduce row.clock,                          -- 0  clk
    M31.reduce row.pc.toNat,                       -- 1  pc
    M31.reduce 0,                                  -- 2  dst_addr (dead)
    M31.reduce row.dstPrevious.limb0.toNat,        -- 3  dst_previous_0
    M31.reduce row.dstPrevious.limb1.toNat,        -- 4  dst_previous_1
    M31.reduce row.dstPrevious.limb2.toNat,        -- 5  dst_previous_2
    M31.reduce row.dstPrevious.limb3.toNat,        -- 6  dst_previous_3
    M31.reduce row.dstPreviousClock,               -- 7  dst_previous_clock
    M31.reduce row.dstNext.limb0.toNat,            -- 8  dst_next_0
    M31.reduce row.dstNext.limb1.toNat,            -- 9  dst_next_1
    M31.reduce row.dstNext.limb2.toNat,            -- 10 dst_next_2
    M31.reduce row.dstNext.limb3.toNat,            -- 11 dst_next_3
    M31.reduce row.rs1Addr.toNat,                  -- 12 rs1_addr
    M31.reduce row.rs1Previous.limb0.toNat,        -- 13 rs1_previous_0
    M31.reduce row.rs1Previous.limb1.toNat,        -- 14 rs1_previous_1
    M31.reduce row.rs1Previous.limb2.toNat,        -- 15 rs1_previous_2
    M31.reduce row.rs1Previous.limb3.toNat,        -- 16 rs1_previous_3
    M31.reduce row.rs1PreviousClock,               -- 17 rs1_previous_clock
    M31.reduce 0,                                  -- 18 src_addr (dead)
    M31.reduce row.srcPrevious.limb0.toNat,        -- 19 src_value_0
    M31.reduce row.srcPrevious.limb1.toNat,        -- 20 src_value_1
    M31.reduce row.srcPrevious.limb2.toNat,        -- 21 src_value_2
    M31.reduce row.srcPrevious.limb3.toNat,        -- 22 src_value_3
    M31.reduce row.srcPreviousClock,               -- 23 src_previous_clock
    M31.reduce row.r2Idx.toNat,                    -- 24 r2_idx
    M31.reduce row.immFelt,                        -- 25 imm_felt
    M31.reduce (bitValue row.srcMsb),              -- 26 src_msb
    M31.reduce row.shiftAmount,                    -- 27 shift_amount
    M31.reduce row.sourceSelector,                 -- 28 src_addr_selector
    M31.reduce row.destinationSelector,            -- 29 dst_addr_selector
    M31.reduce (bitValue row.marker0),             -- 30 markers_0
    M31.reduce (bitValue row.marker1),             -- 31 markers_1
    M31.reduce (bitValue row.marker2),             -- 32 markers_2
    M31.reduce (bitValue row.marker3),             -- 33 markers_3
    M31.reduce (bitValue row.isLb),                -- 34 is_lb
    M31.reduce (bitValue row.isLh),                -- 35 is_lh
    M31.reduce (bitValue row.isLbu),               -- 36 is_lbu
    M31.reduce (bitValue row.isLhu),               -- 37 is_lhu
    M31.reduce (bitValue row.isLw),                -- 38 is_lw
    M31.reduce (bitValue row.isSb),                -- 39 is_sb
    M31.reduce (bitValue row.isSh),                -- 40 is_sh
    M31.reduce (bitValue row.isSw),                -- 41 is_sw
    M31.reduce row.result.limb0.toNat,             -- 42 result_0
    M31.reduce row.result.limb1.toNat,             -- 43 result_1
    M31.reduce row.result.limb2.toNat,             -- 44 result_2
    M31.reduce row.result.limb3.toNat,             -- 45 result_3
    M31.reduce (bitValue row.destinationNonzero),  -- 46 destination_nonzero
    registerInverse row.r2Idx ]                    -- 47 destination_inverse

/-- The side condition the transcription does not carry.

`LoadStoreRow.pc` is a `BitVec 32` and `nextPc` wraps at `2 ^ 32`; the AIR's
`pc` is a single field element and its next-pc node is `pc + 4` in `M31`. The
two agree only when the program counter does not wrap, which is a hypothesis
about the row, not a consequence of `LoadStoreHolds`. -/
structure LoadStoreRowFits (row : LoadStoreRow) : Prop where
  programCounter : row.pc.toNat + 4 < 4294967296

/-! ## The eight-way selector

Roots 0 and 69 together pin the eight opcode flags to exactly one set flag.
Every gate the AIR derives from them is a *field sum* of flag columns, and the
transcription in `Air/Family/LoadStore.lean` spells the same gates as *boolean
disjunctions*; the two agree only because at most one flag is set. That case
split is done once here and consumed by the image lemmas below, so it is not
repeated at each of the 78 roots. -/

private theorem selectorCases (row : LoadStoreRow) (holds : LoadStoreHolds row) :
    (row.isLb = true ∧ row.isLh = false ∧ row.isLbu = false ∧ row.isLhu =
        false ∧ row.isLw = false ∧ row.isSb = false ∧ row.isSh = false ∧
        row.isSw = false) ∨
    (row.isLb = false ∧ row.isLh = true ∧ row.isLbu = false ∧ row.isLhu =
        false ∧ row.isLw = false ∧ row.isSb = false ∧ row.isSh = false ∧
        row.isSw = false) ∨
    (row.isLb = false ∧ row.isLh = false ∧ row.isLbu = true ∧ row.isLhu =
        false ∧ row.isLw = false ∧ row.isSb = false ∧ row.isSh = false ∧
        row.isSw = false) ∨
    (row.isLb = false ∧ row.isLh = false ∧ row.isLbu = false ∧ row.isLhu
        = true ∧ row.isLw = false ∧ row.isSb = false ∧ row.isSh = false ∧
        row.isSw = false) ∨
    (row.isLb = false ∧ row.isLh = false ∧ row.isLbu = false ∧ row.isLhu
        = false ∧ row.isLw = true ∧ row.isSb = false ∧ row.isSh = false ∧
        row.isSw = false) ∨
    (row.isLb = false ∧ row.isLh = false ∧ row.isLbu = false ∧ row.isLhu
        = false ∧ row.isLw = false ∧ row.isSb = true ∧ row.isSh = false ∧
        row.isSw = false) ∨
    (row.isLb = false ∧ row.isLh = false ∧ row.isLbu = false ∧ row.isLhu
        = false ∧ row.isLw = false ∧ row.isSb = false ∧ row.isSh = true ∧
        row.isSw = false) ∨
    (row.isLb = false ∧ row.isLh = false ∧ row.isLbu = false ∧ row.isLhu
        = false ∧ row.isLw = false ∧ row.isSb = false ∧ row.isSh = false ∧
        row.isSw = true) := by
  have sum := holds.selectorSum
  simp only [LoadStoreRow.selectorSum] at sum
  revert sum
  cases row.isLb <;> cases row.isLh <;> cases row.isLbu <;> cases row.isLhu <;>
    cases row.isLw <;> cases row.isSb <;> cases row.isSh <;> cases row.isSw <;>
    intro sum <;>
    first
      | decide
      | exact absurd sum (by decide)

/-! ## The gate images

Each of these says: the field sum of flag columns the AIR uses as a gate is the
image of the boolean gate the transcription uses. All seven are the same
eight-branch case analysis, and each of them is where the one-hot fact is
actually spent. -/

private theorem activeImage (row : LoadStoreRow) (holds : LoadStoreHolds row) :
    M31.reduce (bitValue row.isLb) + M31.reduce (bitValue row.isLh) +
        M31.reduce (bitValue row.isLbu) + M31.reduce (bitValue row.isLhu) +
        M31.reduce (bitValue row.isLw) + M31.reduce (bitValue row.isSb) +
        M31.reduce (bitValue row.isSh) + M31.reduce (bitValue row.isSw) =
      M31.reduce 1 := by
  simp only [M31.reduce_add]
  exact congrArg M31.reduce holds.selectorSum

private theorem signedImage (row : LoadStoreRow) (holds : LoadStoreHolds row) :
    M31.reduce (bitValue row.isLb) + M31.reduce (bitValue row.isLh) =
      M31.reduce (bitValue row.isSigned) := by
  simp only [LoadStoreRow.isSigned]
  rcases selectorCases row holds with
      ⟨a, b, c, d, e, f, g, h⟩ | ⟨a, b, c, d, e, f, g, h⟩ |
      ⟨a, b, c, d, e, f, g, h⟩ | ⟨a, b, c, d, e, f, g, h⟩ |
      ⟨a, b, c, d, e, f, g, h⟩ | ⟨a, b, c, d, e, f, g, h⟩ |
      ⟨a, b, c, d, e, f, g, h⟩ | ⟨a, b, c, d, e, f, g, h⟩ <;>
    simp only [a, b, c, d, e, f, g, h] <;> rfl

private theorem byteImage (row : LoadStoreRow) (holds : LoadStoreHolds row) :
    M31.reduce (bitValue row.isLbu) + M31.reduce (bitValue row.isLb) +
        M31.reduce (bitValue row.isSb) =
      M31.reduce (bitValue row.isByte) := by
  simp only [LoadStoreRow.isByte]
  rcases selectorCases row holds with
      ⟨a, b, c, d, e, f, g, h⟩ | ⟨a, b, c, d, e, f, g, h⟩ |
      ⟨a, b, c, d, e, f, g, h⟩ | ⟨a, b, c, d, e, f, g, h⟩ |
      ⟨a, b, c, d, e, f, g, h⟩ | ⟨a, b, c, d, e, f, g, h⟩ |
      ⟨a, b, c, d, e, f, g, h⟩ | ⟨a, b, c, d, e, f, g, h⟩ <;>
    simp only [a, b, c, d, e, f, g, h] <;> rfl

private theorem halfImage (row : LoadStoreRow) (holds : LoadStoreHolds row) :
    M31.reduce (bitValue row.isLhu) + M31.reduce (bitValue row.isLh) +
        M31.reduce (bitValue row.isSh) =
      M31.reduce (bitValue row.isHalf) := by
  simp only [LoadStoreRow.isHalf]
  rcases selectorCases row holds with
      ⟨a, b, c, d, e, f, g, h⟩ | ⟨a, b, c, d, e, f, g, h⟩ |
      ⟨a, b, c, d, e, f, g, h⟩ | ⟨a, b, c, d, e, f, g, h⟩ |
      ⟨a, b, c, d, e, f, g, h⟩ | ⟨a, b, c, d, e, f, g, h⟩ |
      ⟨a, b, c, d, e, f, g, h⟩ | ⟨a, b, c, d, e, f, g, h⟩ <;>
    simp only [a, b, c, d, e, f, g, h] <;> rfl

private theorem storeImage (row : LoadStoreRow) (holds : LoadStoreHolds row) :
    M31.reduce (bitValue row.isSb) + M31.reduce (bitValue row.isSh) +
        M31.reduce (bitValue row.isSw) =
      M31.reduce (bitValue row.isStore) := by
  simp only [LoadStoreRow.isStore]
  rcases selectorCases row holds with
      ⟨a, b, c, d, e, f, g, h⟩ | ⟨a, b, c, d, e, f, g, h⟩ |
      ⟨a, b, c, d, e, f, g, h⟩ | ⟨a, b, c, d, e, f, g, h⟩ |
      ⟨a, b, c, d, e, f, g, h⟩ | ⟨a, b, c, d, e, f, g, h⟩ |
      ⟨a, b, c, d, e, f, g, h⟩ | ⟨a, b, c, d, e, f, g, h⟩ <;>
    simp only [a, b, c, d, e, f, g, h] <;> rfl

private theorem byteLoadImage (row : LoadStoreRow) (holds : LoadStoreHolds row) :
    M31.reduce (bitValue row.isLb) + M31.reduce (bitValue row.isLbu) =
      M31.reduce (bitValue row.isByteLoad) := by
  simp only [LoadStoreRow.isByteLoad]
  rcases selectorCases row holds with
      ⟨a, b, c, d, e, f, g, h⟩ | ⟨a, b, c, d, e, f, g, h⟩ |
      ⟨a, b, c, d, e, f, g, h⟩ | ⟨a, b, c, d, e, f, g, h⟩ |
      ⟨a, b, c, d, e, f, g, h⟩ | ⟨a, b, c, d, e, f, g, h⟩ |
      ⟨a, b, c, d, e, f, g, h⟩ | ⟨a, b, c, d, e, f, g, h⟩ <;>
    simp only [a, b, c, d, e, f, g, h] <;> rfl

private theorem halfLoadImage (row : LoadStoreRow) (holds : LoadStoreHolds row) :
    M31.reduce (bitValue row.isLh) + M31.reduce (bitValue row.isLhu) =
      M31.reduce (bitValue row.isHalfLoad) := by
  simp only [LoadStoreRow.isHalfLoad]
  rcases selectorCases row holds with
      ⟨a, b, c, d, e, f, g, h⟩ | ⟨a, b, c, d, e, f, g, h⟩ |
      ⟨a, b, c, d, e, f, g, h⟩ | ⟨a, b, c, d, e, f, g, h⟩ |
      ⟨a, b, c, d, e, f, g, h⟩ | ⟨a, b, c, d, e, f, g, h⟩ |
      ⟨a, b, c, d, e, f, g, h⟩ | ⟨a, b, c, d, e, f, g, h⟩ <;>
    simp only [a, b, c, d, e, f, g, h] <;> rfl

/-- Node 88 of the export: `active - is_store`, which is `is_load` once
`activeImage` and `storeImage` have fired. -/
private theorem loadImage (row : LoadStoreRow) :
    M31.reduce 1 - M31.reduce (bitValue row.isStore) =
      M31.reduce (bitValue row.isLoad) := by
  simp only [LoadStoreRow.isLoad]
  cases row.isStore <;> rfl

/-- The opcode identifier the AIR materialises on the program bus. -/
private theorem opcodeImage (row : LoadStoreRow) (holds : LoadStoreHolds row) :
    M31.reduce (bitValue row.isLb) * M31.reduce 19 +
        M31.reduce (bitValue row.isLh) * M31.reduce 20 +
        M31.reduce (bitValue row.isLw) * M31.reduce 21 +
        M31.reduce (bitValue row.isLbu) * M31.reduce 22 +
        M31.reduce (bitValue row.isLhu) * M31.reduce 23 +
        M31.reduce (bitValue row.isSb) * M31.reduce 24 +
        M31.reduce (bitValue row.isSh) * M31.reduce 25 +
        M31.reduce (bitValue row.isSw) * M31.reduce 26 =
      M31.reduce row.opcodeId := by
  simp only [LoadStoreRow.opcodeId]
  rcases selectorCases row holds with
      ⟨a, b, c, d, e, f, g, h⟩ | ⟨a, b, c, d, e, f, g, h⟩ |
      ⟨a, b, c, d, e, f, g, h⟩ | ⟨a, b, c, d, e, f, g, h⟩ |
      ⟨a, b, c, d, e, f, g, h⟩ | ⟨a, b, c, d, e, f, g, h⟩ |
      ⟨a, b, c, d, e, f, g, h⟩ | ⟨a, b, c, d, e, f, g, h⟩ <;>
    simp only [a, b, c, d, e, f, g, h] <;> rfl

/-- Exactly one of the three width classes fires; C15 needs this. -/
private theorem widthCases (row : LoadStoreRow) (holds : LoadStoreHolds row) :
    (row.isByte = true ∧ row.isHalf = false ∧ row.isWord = false) ∨
      (row.isByte = false ∧ row.isHalf = true ∧ row.isWord = false) ∨
      (row.isByte = false ∧ row.isHalf = false ∧ row.isWord = true) := by
  simp only [LoadStoreRow.isByte, LoadStoreRow.isHalf, LoadStoreRow.isWord]
  rcases selectorCases row holds with
      ⟨a, b, c, d, e, f, g, h⟩ | ⟨a, b, c, d, e, f, g, h⟩ |
      ⟨a, b, c, d, e, f, g, h⟩ | ⟨a, b, c, d, e, f, g, h⟩ |
      ⟨a, b, c, d, e, f, g, h⟩ | ⟨a, b, c, d, e, f, g, h⟩ |
      ⟨a, b, c, d, e, f, g, h⟩ | ⟨a, b, c, d, e, f, g, h⟩ <;>
    simp only [a, b, c, d, e, f, g, h] <;> decide

/-- `is_lw` and `is_sw` are never both set; C42-C45 need this. -/
private theorem wordCases (row : LoadStoreRow) (holds : LoadStoreHolds row) :
    (row.isLw = false ∧ row.isSw = false) ∨ (row.isLw = true ∧ row.isSw = false) ∨
      (row.isLw = false ∧ row.isSw = true) := by
  rcases selectorCases row holds with
      ⟨a, b, c, d, e, f, g, h⟩ | ⟨a, b, c, d, e, f, g, h⟩ |
      ⟨a, b, c, d, e, f, g, h⟩ | ⟨a, b, c, d, e, f, g, h⟩ |
      ⟨a, b, c, d, e, f, g, h⟩ | ⟨a, b, c, d, e, f, g, h⟩ |
      ⟨a, b, c, d, e, f, g, h⟩ | ⟨a, b, c, d, e, f, g, h⟩ <;>
    simp only [a, b, c, d, e, f, g, h] <;> decide

/-! ## The derived scalar images

`marker_sum`, `shift_id`, the sign-extension mask, the effective address and the
aligned-address quarter. The last two are where the arithmetic actually lives:
the AIR divides by four and by two, and both divisions are multiplications by
the corresponding inverse in `M31`. -/

private theorem markerSumImage (row : LoadStoreRow) :
    M31.reduce 0 + M31.reduce (bitValue row.marker0) +
        M31.reduce (bitValue row.marker1) + M31.reduce (bitValue row.marker2) +
        M31.reduce (bitValue row.marker3) =
      M31.reduce row.markerSum := by
  simp only [M31.reduce_add, LoadStoreRow.markerSum, Nat.zero_add]

private theorem shiftIdImage (row : LoadStoreRow) :
    M31.reduce 0 + M31.reduce (bitValue row.marker0) * M31.reduce 0 +
        M31.reduce (bitValue row.marker1) * M31.reduce 1 +
        M31.reduce (bitValue row.marker2) * M31.reduce 2 +
        M31.reduce (bitValue row.marker3) * M31.reduce 3 =
      M31.reduce row.shiftId := by
  simp only [LoadStoreRow.shiftId]
  cases row.marker0 <;> cases row.marker1 <;> cases row.marker2 <;>
    cases row.marker3 <;> rfl

private theorem signMaskImage (row : LoadStoreRow) :
    M31.reduce (bitValue row.isSigned) * M31.reduce (bitValue row.srcMsb) *
        M31.reduce 255 =
      M31.reduce row.signMask.toNat := by
  simp only [LoadStoreRow.signMask]
  cases row.isSigned <;> cases row.srcMsb <;> rfl

/-- The two width branches of C15 bound `shift_amount` by three, which is what
makes the effective-address image below canonical. -/
private theorem shiftAmountSmall (row : LoadStoreRow) (holds : LoadStoreHolds row) :
    row.shiftAmount ≤ 3 := by
  rcases widthCases row holds with ⟨b, _, _⟩ | ⟨_, h, _⟩ | ⟨_, _, w⟩
  · rw [holds.byteShiftAmount b]
    have oneHot := holds.byteMarkerSum b
    revert oneHot
    simp only [LoadStoreRow.markerSum, LoadStoreRow.shiftId]
    cases row.marker0 <;> cases row.marker1 <;> cases row.marker2 <;>
      cases row.marker3 <;> intro oneHot <;>
      first
        | decide
        | exact absurd oneHot (by decide)
  · have amount := holds.halfShiftAmount h
    have shift := holds.halfShiftId h
    omega
  · rw [holds.wordShiftAmount w]
    omega

private theorem alignedAddressSmall (row : LoadStoreRow) (holds : LoadStoreHolds row) :
    row.alignedAddress < 4194304 := by
  have quarter := holds.alignedQuarterRange
  simp only [LoadStoreRow.alignedAddress]
  omega

/-- The AIR recomputes the effective address as
`compose(rs1_next) + imm_felt`, subtracts `shift_amount` and never commits the
result. This is the step that says the difference is the aligned word address
the transcription carries. -/
private theorem effectiveAddressImage (row : LoadStoreRow) (holds : LoadStoreHolds row) :
    ((M31.reduce row.rs1Previous.limb3.toNat * M31.reduce 256 +
                M31.reduce row.rs1Previous.limb2.toNat) * M31.reduce 256 +
              M31.reduce row.rs1Previous.limb1.toNat) * M31.reduce 256 +
          M31.reduce row.rs1Previous.limb0.toNat +
        M31.reduce row.immFelt -
      M31.reduce row.shiftAmount =
    M31.reduce row.alignedAddress := by
  have small := shiftAmountSmall row holds
  have aligned := alignedAddressSmall row holds
  have address : (row.rs1Previous.value + row.immFelt) % M31.modulus =
      row.alignedAddress + row.shiftAmount := holds.memoryAddress
  simp only [M31.reduce_mul, M31.reduce_add]
  have compose :
      ((row.rs1Previous.limb3.toNat * 256 + row.rs1Previous.limb2.toNat) * 256 +
                row.rs1Previous.limb1.toNat) * 256 + row.rs1Previous.limb0.toNat +
            row.immFelt =
          row.rs1Previous.value + row.immFelt := by
    simp only [WordBytes.value]
    omega
  rw [compose]
  have canonical : M31.reduce (row.rs1Previous.value + row.immFelt) =
      M31.reduce (row.alignedAddress + row.shiftAmount) := by
    apply M31.eq_of_val
    simp only [M31.val_reduce, address]
    refine (Nat.mod_eq_of_lt ?_).symm
    simp only [M31.modulus, RiscvRefinement.Air.Bridge.m31Modulus]
    omega
  rw [canonical,
    M31.reduce_sub _ _ (Nat.le_add_left row.shiftAmount row.alignedAddress)]
  congr 1
  omega

/-- C16: the AIR routes the aligned address to `src_addr_selector` on a load
and `r2_idx` on a store. -/
private theorem sourceSelectorImage (row : LoadStoreRow) :
    M31.reduce (bitValue row.isLoad) * M31.reduce row.alignedAddress +
        M31.reduce (bitValue row.isStore) * M31.reduce row.r2Idx.toNat =
      M31.reduce row.sourceSelector := by
  simp only [LoadStoreRow.sourceSelector, LoadStoreRow.isLoad]
  cases row.isStore with
  | false =>
      show M31.reduce (bitValue true) * M31.reduce row.alignedAddress +
          M31.reduce (bitValue false) * M31.reduce row.r2Idx.toNat =
        M31.reduce row.alignedAddress
      simp only [bitValue_true, bitValue_false, M31.reduce_zero, M31.zero_mul,
        M31.one_mul, M31.add_zero]
  | true =>
      show M31.reduce (bitValue false) * M31.reduce row.alignedAddress +
          M31.reduce (bitValue true) * M31.reduce row.r2Idx.toNat =
        M31.reduce row.r2Idx.toNat
      simp only [bitValue_true, bitValue_false, M31.reduce_zero, M31.zero_mul,
        M31.one_mul, M31.zero_add]

/-- C17: the mirror image of `sourceSelectorImage`. -/
private theorem destinationSelectorImage (row : LoadStoreRow) :
    M31.reduce (bitValue row.isLoad) * M31.reduce row.r2Idx.toNat +
        M31.reduce (bitValue row.isStore) * M31.reduce row.alignedAddress =
      M31.reduce row.destinationSelector := by
  simp only [LoadStoreRow.destinationSelector, LoadStoreRow.isLoad]
  cases row.isStore with
  | false =>
      show M31.reduce (bitValue true) * M31.reduce row.r2Idx.toNat +
          M31.reduce (bitValue false) * M31.reduce row.alignedAddress =
        M31.reduce row.r2Idx.toNat
      simp only [bitValue_true, bitValue_false, M31.reduce_zero, M31.zero_mul,
        M31.one_mul, M31.add_zero]
  | true =>
      show M31.reduce (bitValue false) * M31.reduce row.r2Idx.toNat +
          M31.reduce (bitValue true) * M31.reduce row.alignedAddress =
        M31.reduce row.alignedAddress
      simp only [bitValue_true, bitValue_false, M31.reduce_zero, M31.zero_mul,
        M31.one_mul, M31.zero_add]

/-- L06, the alignment request. `src_addr_selector + dst_addr_selector - r2_idx`
is the aligned word address whichever direction the row runs in, and the AIR
multiplies it by `4⁻¹`. -/
private theorem alignedQuarterImage (row : LoadStoreRow) :
    (M31.reduce row.sourceSelector + M31.reduce row.destinationSelector -
          M31.reduce row.r2Idx.toNat) * M31.reduce 536870912 =
      M31.reduce row.alignedQuarter := by
  have selectors : row.sourceSelector + row.destinationSelector =
      row.alignedAddress + row.r2Idx.toNat := by
    simp only [LoadStoreRow.sourceSelector, LoadStoreRow.destinationSelector]
    cases row.isStore with
    | false => show row.alignedAddress + row.r2Idx.toNat = _; rfl
    | true => show row.r2Idx.toNat + row.alignedAddress = _; omega
  rw [M31.reduce_add, selectors,
    M31.reduce_sub _ _ (Nat.le_add_left row.r2Idx.toNat row.alignedAddress),
    show row.alignedAddress + row.r2Idx.toNat - row.r2Idx.toNat =
      row.alignedAddress from by omega,
    LoadStoreRow.alignedAddress, M31.reduce_mul]
  exact M31.reduce_quarter row.alignedQuarter

/-! ## Small shape lemmas the root proofs consume -/

private theorem bitFalse : M31.reduce (bitValue false) = 0 := rfl

private theorem bitFalseSum :
    M31.reduce (bitValue false) + M31.reduce (bitValue false) = 0 := rfl

private theorem oneSubBitTrue : M31.reduce 1 - M31.reduce (bitValue true) = 0 :=
  M31.sub_self 1

private theorem limbSub {left right : Byte} (equal : left = right) :
    M31.reduce left.toNat - M31.reduce right.toNat = 0 := by
  rw [equal]
  exact M31.sub_self _

/-- Roots 24-31: `gate * (x - y) * marker`. -/
private theorem markerGated {gate marker left right : M31}
    (reason : marker = 0 ∨ gate = 0 ∨ left = right) :
    gate * (left - right) * marker = 0 := by
  rcases reason with reason | reason | reason
  · exact mulRightZero reason
  · exact mulLeftZero (mulLeftZero reason)
  · exact mulLeftZero (mulRightZero (subZero reason))

/-- Roots 61-64: `dst_next_i - destination_nonzero * result_i`. -/
private theorem loadDestinationVanishes {flagBit : Bool} {nextValue resultValue : Nat}
    (equation : nextValue = if flagBit then resultValue else 0) :
    M31.reduce nextValue -
        M31.reduce (bitValue flagBit) * M31.reduce resultValue = 0 := by
  cases flagBit with
  | false =>
      simp only [Bool.false_eq_true, if_false] at equation
      rw [equation]
      simp only [bitValue_false, M31.reduce_zero, M31.zero_mul]
      exact M31.sub_cancel 0
  | true =>
      simp only [if_true] at equation
      rw [equation, bitValue_true, M31.reduce_mul, Nat.one_mul]
      exact M31.sub_self _

private theorem storeOfNotLoad {row : LoadStoreRow} (direction : row.isLoad = false) :
    row.isStore = true := by
  simp only [LoadStoreRow.isLoad] at direction
  cases store : row.isStore with
  | false => rw [store] at direction; exact absurd direction (by decide)
  | true => rfl

private theorem halfOfHalfLoad {row : LoadStoreRow} (load : row.isHalfLoad = true) :
    row.isHalf = true := by
  revert load
  simp only [LoadStoreRow.isHalf, LoadStoreRow.isHalfLoad]
  cases row.isLh <;> cases row.isLhu <;> cases row.isSh <;> intro load <;>
    first
      | decide
      | exact absurd load (by decide)

private theorem halfOfStoreHalf {row : LoadStoreRow} (store : row.isSh = true) :
    row.isHalf = true := by
  revert store
  simp only [LoadStoreRow.isHalf]
  cases row.isLh <;> cases row.isLhu <;> cases row.isSh <;> intro store <;>
    first
      | decide
      | exact absurd store (by decide)

/-- The half-word placement gates. C20 pins `shift_id` to `1` or `5`, and
`(5 - shift_id) / 4` and `(shift_id - 1) / 4` are then the two indicators. -/
private theorem lowHalfOne {row : LoadStoreRow} (shift : row.shiftId = 1) :
    (M31.reduce 5 - M31.reduce row.shiftId) * M31.reduce 536870912 = M31.reduce 1 := by
  rw [shift, M31.reduce_sub _ _ (by omega), M31.reduce_mul]
  rfl

private theorem lowHalfNil {row : LoadStoreRow} (shift : row.shiftId = 5) :
    (M31.reduce 5 - M31.reduce row.shiftId) * M31.reduce 536870912 = 0 := by
  rw [shift]
  exact mulLeftZero (M31.sub_self 5)

private theorem highHalfOne {row : LoadStoreRow} (shift : row.shiftId = 5) :
    (M31.reduce row.shiftId - M31.reduce 1) * M31.reduce 536870912 = M31.reduce 1 := by
  rw [shift, M31.reduce_sub _ _ (by omega), M31.reduce_mul]
  rfl

private theorem highHalfNil {row : LoadStoreRow} (shift : row.shiftId = 1) :
    (M31.reduce row.shiftId - M31.reduce 1) * M31.reduce 536870912 = 0 := by
  rw [shift]
  exact mulLeftZero (M31.sub_self 1)

/-- The two half-word placement gates are complementary, and in particular
neither is identically zero. Without this the C34-C41 proofs below would be
equally consistent with both gates being dead, which would make those eight
roots vacuous — the proofs only ever need one of the two to vanish. -/
theorem halfPlacementGates (row : LoadStoreRow)
    (shift : row.shiftId = 1 ∨ row.shiftId = 5) :
    ((M31.reduce 5 - M31.reduce row.shiftId) * M31.reduce 536870912 = M31.reduce 1 ∧
        (M31.reduce row.shiftId - M31.reduce 1) * M31.reduce 536870912 = 0) ∨
      ((M31.reduce 5 - M31.reduce row.shiftId) * M31.reduce 536870912 = 0 ∧
        (M31.reduce row.shiftId - M31.reduce 1) * M31.reduce 536870912 =
          M31.reduce 1) := by
  rcases shift with shift | shift
  · exact Or.inl ⟨lowHalfOne shift, highHalfNil shift⟩
  · exact Or.inr ⟨lowHalfNil shift, highHalfOne shift⟩

private theorem r2NonzeroImage (row : LoadStoreRow) (holds : LoadStoreHolds row) :
    row.destinationNonzero = decide (row.r2Idx.toNat ≠ 0) := by
  have index : (row.r2Idx = zeroRegister) ↔ (row.r2Idx.toNat = 0) := by
    constructor
    · intro equal
      rw [equal]
      rfl
    · intro equal
      apply BitVec.eq_of_toNat_eq
      rw [equal]
      rfl
  rw [holds.destinationFlag]
  simp only [ne_eq, index]

private theorem bitValue_eq_flagValue (flag : Bool) : bitValue flag = flagValue flag := by
  cases flag <;> rfl

private theorem nextPcImage (row : LoadStoreRow) (holds : LoadStoreHolds row)
    (fits : LoadStoreRowFits row) :
    row.claimedNextPc.toNat = row.pc.toNat + 4 := by
  have wrap := fits.programCounter
  simp only [LoadStoreRow.claimedNextPc, RiscvRefinement.nextPc, BitVec.toNat_add,
    BitVec.toNat_ofNat, Nat.reducePow]
  omega

private theorem accessClockImage (row : LoadStoreRow) (holds : LoadStoreHolds row)
    (ordinal : Nat) :
    (M31.reduce row.clock - M31.reduce 1) * M31.reduce 4 + M31.reduce ordinal =
      M31.reduce (accessClock row.clock ordinal) := by
  have positive := holds.clockPositive
  rw [M31.reduce_sub _ _ positive, M31.reduce_mul, M31.reduce_add]
  congr 1

/-- The three `range_check_20` clock requests carry `current - previous - 1`. -/
private theorem gapImage (current previous : Nat) (order : previous < current) :
    M31.reduce current - M31.reduce previous - M31.reduce 1 =
      M31.reduce (current - previous - 1) := by
  rw [M31.reduce_sub _ _ (Nat.le_of_lt order), M31.reduce_sub _ _ (by omega)]

/-! ## Routing the two swapping access blocks to their clock obligations

`LoadStoreHolds` states the clock obligations by *role* — `operandClock` at
ordinal two, `memoryClock` at ordinal three — while the AIR states them by
*block*, `src` and `dst`. These two lemmas are the routing, and they are where
the address-space swap actually shows up. -/

private theorem sourceClockValid (row : LoadStoreRow) (holds : LoadStoreHolds row) :
    validPreviousClock row.srcPreviousClock (sourceAccessClock row) := by
  cases direction : row.isStore with
  | false =>
      rw [sourceAccessClock_load row direction]
      have valid := holds.memoryClock
      simp only [LoadStoreRow.memoryPreviousClock] at valid
      rw [direction] at valid
      exact valid
  | true =>
      rw [sourceAccessClock_store row direction]
      have valid := holds.operandClock
      simp only [LoadStoreRow.operandPreviousClock] at valid
      rw [direction] at valid
      exact valid

private theorem destinationClockValid (row : LoadStoreRow) (holds : LoadStoreHolds row) :
    validPreviousClock row.dstPreviousClock (destinationAccessClock row) := by
  cases direction : row.isStore with
  | false =>
      rw [destinationAccessClock_load row direction]
      have valid := holds.operandClock
      simp only [LoadStoreRow.operandPreviousClock] at valid
      rw [direction] at valid
      exact valid
  | true =>
      rw [destinationAccessClock_store row direction]
      have valid := holds.memoryClock
      simp only [LoadStoreRow.memoryPreviousClock] at valid
      rw [direction] at valid
      exact valid

private theorem baseGapImage (row : LoadStoreRow) (holds : LoadStoreHolds row) :
    (M31.reduce row.clock - M31.reduce 1) * M31.reduce 4 + M31.reduce 1 -
          M31.reduce row.rs1PreviousClock - M31.reduce 1 =
      M31.reduce (accessClock row.clock 1 - row.rs1PreviousClock - 1) := by
  rw [accessClockImage row holds 1]
  exact gapImage _ _ holds.baseClock.1

private theorem sourceGapImage (row : LoadStoreRow) (holds : LoadStoreHolds row) :
    (M31.reduce row.clock - M31.reduce 1) * M31.reduce 4 + M31.reduce 2 +
          M31.reduce (bitValue row.isLoad) - M31.reduce row.srcPreviousClock -
          M31.reduce 1 =
      M31.reduce (sourceAccessClock row - row.srcPreviousClock - 1) := by
  rw [accessClockImage row holds 2, M31.reduce_add]
  exact gapImage _ _ (sourceClockValid row holds).1

private theorem destinationGapImage (row : LoadStoreRow) (holds : LoadStoreHolds row) :
    (M31.reduce row.clock - M31.reduce 1) * M31.reduce 4 + M31.reduce 2 +
          M31.reduce (bitValue row.isStore) - M31.reduce row.dstPreviousClock -
          M31.reduce 1 =
      M31.reduce (destinationAccessClock row - row.dstPreviousClock - 1) := by
  rw [accessClockImage row holds 2, M31.reduce_add]
  exact gapImage _ _ (destinationClockValid row holds).1

private theorem sourceAccessClockImage (row : LoadStoreRow) (holds : LoadStoreHolds row) :
    (M31.reduce row.clock - M31.reduce 1) * M31.reduce 4 + M31.reduce 2 +
        M31.reduce (bitValue row.isLoad) =
      M31.reduce (sourceAccessClock row) := by
  rw [accessClockImage row holds 2, M31.reduce_add]
  rfl

private theorem destinationAccessClockImage (row : LoadStoreRow)
    (holds : LoadStoreHolds row) :
    (M31.reduce row.clock - M31.reduce 1) * M31.reduce 4 + M31.reduce 2 +
        M31.reduce (bitValue row.isStore) =
      M31.reduce (destinationAccessClock row) := by
  rw [accessClockImage row holds 2, M31.reduce_add]
  rfl

/-- The reserved last row of `range_check_m31` is `(255, 127)`; the two sign
requests have first coordinate `0`, so the exclusion never bites. -/
private theorem zeroNotReserved (value : M31) :
    (decide ((M31.reduce 0).toNat = 255) && decide (value.toNat = 127)) = false := by
  rw [show (decide ((M31.reduce 0).toNat = 255)) = false from by decide, Bool.false_and]

/-- L14 / L15: `result_i - 128 * src_msb` is a seven-bit residue exactly because
`src_msb` is bit seven of `result_i`. This is the only place the sign witness
is spent, and it is a lookup, not a constraint root. -/
private theorem msbResidue (byte : Byte) (msb : Bool)
    (witness : msb = byte.getLsbD 7) :
    M31.reduce byte.toNat - M31.reduce (bitValue msb) * M31.reduce 128 =
        M31.reduce (byte.toNat - 128 * bitValue msb) ∧
      byte.toNat - 128 * bitValue msb < 128 := by
  have bound := byte.isLt
  simp only [Nat.reducePow] at bound
  have bit : byte.getLsbD 7 = decide (byte.toNat / 2 ^ 7 % 2 = 1) := by
    simp only [BitVec.getLsbD, Nat.testBit_eq_decide_div_mod_eq]
  rw [bit] at witness
  cases msb with
  | false =>
      have clear : ¬ (byte.toNat / 2 ^ 7 % 2 = 1) := by simpa using witness.symm
      simp only [Nat.reducePow] at clear
      simp only [bitValue_false, M31.reduce_zero, M31.zero_mul, Nat.mul_zero,
        Nat.sub_zero]
      exact ⟨M31.sub_zero _, by omega⟩
  | true =>
      have set : byte.toNat / 2 ^ 7 % 2 = 1 := by simpa using witness.symm
      simp only [Nat.reducePow] at set
      simp only [bitValue_true, M31.reduce_mul, Nat.one_mul, Nat.mul_one]
      exact ⟨M31.reduce_sub _ _ (by omega), by omega⟩

/-! ## The bridge for the constraint roots

The proof has one shape: unfold the encoded node table under the column
assignment — this *is* the evaluation of the production AIR — and discharge the
63 resulting `M31` identities from `LoadStoreHolds`. -/

/-- Every constraint root of the encoded production `load_store` AIR evaluates
to zero under `loadStoreColumns row`, for every row the transcription accepts. -/
theorem loadStoreConstraintValues (row : LoadStoreRow) (holds : LoadStoreHolds row)
    (fits : LoadStoreRowFits row) :
    loadStoreCircuitCompiled.constraintValues (loadStoreColumns row) =
      List.replicate 63 0 := by
  try simp only [LoadStoreRow.rs1Next, LoadStoreRow.srcNext] at holds
  simp only [MulhCircuit.constraintValues, MulhCircuit.values, MulhCircuit.value,
    MulhCircuit.nodeValuesRev, loadStoreCircuitCompiled, loadStoreCircuit, evalLoop,
    Node.evalLocal, nth, List.map_cons, List.map_nil, loadStoreColumns, List.replicate,
    List.cons.injEq, and_true]
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_,
    ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_,
    ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_,
    ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  -- C00: booleanity of the eight-way selector sum
  · rw [activeImage row holds]
    exact mulRightZero (M31.sub_self 1)
  -- C01-C08: booleanity of each of the eight opcode flags
  · exact bitBooleanVanishes row.isLb
  · exact bitBooleanVanishes row.isLh
  · exact bitBooleanVanishes row.isLbu
  · exact bitBooleanVanishes row.isLhu
  · exact bitBooleanVanishes row.isLw
  · exact bitBooleanVanishes row.isSb
  · exact bitBooleanVanishes row.isSh
  · exact bitBooleanVanishes row.isSw
  -- C09: booleanity of the sign witness
  · exact bitBooleanVanishes row.srcMsb
  -- C10: (1 - is_signed) * src_msb
  · rw [signedImage row holds]
    cases msb : row.srcMsb with
    | false => exact mulRightZero bitFalse
    | true =>
        have signed : row.isSigned = true := by
          cases sign : row.isSigned with
          | false =>
              rw [holds.signWitnessCanonical sign] at msb
              exact absurd msb (by decide)
          | true => rfl
        rw [signed]
        exact mulLeftZero oneSubBitTrue
  -- C11-C14: booleanity of the four markers
  · exact bitBooleanVanishes row.marker0
  · exact bitBooleanVanishes row.marker1
  · exact bitBooleanVanishes row.marker2
  · exact bitBooleanVanishes row.marker3
  -- C15: shift_amount = opcode_b * shift_id + opcode_h * (shift_id - 1) / 2
  · rw [byteImage row holds, halfImage row holds, shiftIdImage row]
    rcases widthCases row holds with ⟨b, h, _⟩ | ⟨b, h, _⟩ | ⟨b, h, w⟩
    · rw [b, h, holds.byteShiftAmount b]
      simp only [bitValue_true, bitValue_false, M31.reduce_zero, M31.zero_mul,
        M31.one_mul, M31.add_zero]
      exact M31.sub_self _
    · rw [b, h]
      simp only [bitValue_true, bitValue_false, M31.reduce_zero, M31.zero_mul,
        M31.one_mul, M31.zero_add]
      have amount := holds.halfShiftAmount h
      rw [← amount, M31.reduce_sub _ _ (by omega),
        show 2 * row.shiftAmount + 1 - 1 = 2 * row.shiftAmount from by omega,
        M31.reduce_mul, M31.reduce_half]
      exact M31.sub_self _
    · rw [b, h, holds.wordShiftAmount w]
      simp only [bitValue_false, M31.reduce_zero, M31.zero_mul, M31.add_zero]
      exact M31.sub_cancel 0
  -- C16: src_addr_selector
  · rw [activeImage row holds, storeImage row holds, loadImage row,
      effectiveAddressImage row holds, sourceSelectorImage row]
    exact M31.sub_self _
  -- C17: dst_addr_selector
  · rw [activeImage row holds, storeImage row holds, loadImage row,
      effectiveAddressImage row holds, destinationSelectorImage row]
    exact M31.sub_self _
  -- C18: opcode_b * (1 - marker_sum)
  · rw [byteImage row holds, markerSumImage row]
    cases width : row.isByte with
    | false => exact mulLeftZero bitFalse
    | true => exact mulRightZero (by rw [holds.byteMarkerSum width]; exact M31.sub_self 1)
  -- C19: opcode_h * (2 - marker_sum)
  · rw [halfImage row holds, markerSumImage row]
    cases width : row.isHalf with
    | false => exact mulLeftZero bitFalse
    | true => exact mulRightZero (by rw [holds.halfMarkerSum width]; exact M31.sub_self 2)
  -- C20: opcode_h * (1 - shift_id) * (5 - shift_id)
  · rw [halfImage row holds, shiftIdImage row]
    cases width : row.isHalf with
    | false => exact mulLeftZero (mulLeftZero bitFalse)
    | true =>
        rcases holds.halfShiftId width with shift | shift
        · exact mulLeftZero (mulRightZero (by rw [shift]; exact M31.sub_self 1))
        · exact mulRightZero (by rw [shift]; exact M31.sub_self 5)
  -- C21-C23: load_b * (signed_mask - result_i), i = 1, 2, 3
  · rw [byteLoadImage row holds, signedImage row holds, signMaskImage row]
    cases load : row.isByteLoad with
    | false => exact mulLeftZero bitFalse
    | true =>
        refine mulRightZero ?_
        rw [(holds.byteLoadExtension load).1]
        exact M31.sub_self _
  · rw [byteLoadImage row holds, signedImage row holds, signMaskImage row]
    cases load : row.isByteLoad with
    | false => exact mulLeftZero bitFalse
    | true =>
        refine mulRightZero ?_
        rw [(holds.byteLoadExtension load).2.1]
        exact M31.sub_self _
  · rw [byteLoadImage row holds, signedImage row holds, signMaskImage row]
    cases load : row.isByteLoad with
    | false => exact mulLeftZero bitFalse
    | true =>
        refine mulRightZero ?_
        rw [(holds.byteLoadExtension load).2.2]
        exact M31.sub_self _
  -- C24-C31: the byte-selection ladder, interleaved load / store
  · rw [byteLoadImage row holds]
    refine markerGated ?_
    cases mark : row.marker0 with
    | false => exact Or.inl bitFalse
    | true =>
        cases load : row.isByteLoad with
        | false => exact Or.inr (Or.inl bitFalse)
        | true => exact Or.inr (Or.inr (by rw [(holds.byteLoadSelect load).1 mark]))
  · refine markerGated ?_
    cases mark : row.marker0 with
    | false => exact Or.inl bitFalse
    | true =>
        cases store : row.isSb with
        | false => exact Or.inr (Or.inl bitFalse)
        | true => exact Or.inr (Or.inr (by rw [(holds.byteStoreSelect store).1 mark]))
  · rw [byteLoadImage row holds]
    refine markerGated ?_
    cases mark : row.marker1 with
    | false => exact Or.inl bitFalse
    | true =>
        cases load : row.isByteLoad with
        | false => exact Or.inr (Or.inl bitFalse)
        | true => exact Or.inr (Or.inr (by rw [(holds.byteLoadSelect load).2.1 mark]))
  · refine markerGated ?_
    cases mark : row.marker1 with
    | false => exact Or.inl bitFalse
    | true =>
        cases store : row.isSb with
        | false => exact Or.inr (Or.inl bitFalse)
        | true => exact Or.inr (Or.inr (by rw [(holds.byteStoreSelect store).2.1 mark]))
  · rw [byteLoadImage row holds]
    refine markerGated ?_
    cases mark : row.marker2 with
    | false => exact Or.inl bitFalse
    | true =>
        cases load : row.isByteLoad with
        | false => exact Or.inr (Or.inl bitFalse)
        | true => exact Or.inr (Or.inr (by rw [(holds.byteLoadSelect load).2.2.1 mark]))
  · refine markerGated ?_
    cases mark : row.marker2 with
    | false => exact Or.inl bitFalse
    | true =>
        cases store : row.isSb with
        | false => exact Or.inr (Or.inl bitFalse)
        | true => exact Or.inr (Or.inr (by rw [(holds.byteStoreSelect store).2.2.1 mark]))
  · rw [byteLoadImage row holds]
    refine markerGated ?_
    cases mark : row.marker3 with
    | false => exact Or.inl bitFalse
    | true =>
        cases load : row.isByteLoad with
        | false => exact Or.inr (Or.inl bitFalse)
        | true => exact Or.inr (Or.inr (by rw [(holds.byteLoadSelect load).2.2.2 mark]))
  · refine markerGated ?_
    cases mark : row.marker3 with
    | false => exact Or.inl bitFalse
    | true =>
        cases store : row.isSb with
        | false => exact Or.inr (Or.inl bitFalse)
        | true => exact Or.inr (Or.inr (by rw [(holds.byteStoreSelect store).2.2.2 mark]))
  -- C32-C33: load_h * (signed_mask - result_i), i = 2, 3
  · rw [halfLoadImage row holds, signedImage row holds, signMaskImage row]
    cases load : row.isHalfLoad with
    | false => exact mulLeftZero bitFalse
    | true =>
        refine mulRightZero ?_
        rw [(holds.halfLoadExtension load).1]
        exact M31.sub_self _
  · rw [halfLoadImage row holds, signedImage row holds, signMaskImage row]
    cases load : row.isHalfLoad with
    | false => exact mulLeftZero bitFalse
    | true =>
        refine mulRightZero ?_
        rw [(holds.halfLoadExtension load).2]
        exact M31.sub_self _
  -- C34-C37: half-word load placement
  · rw [halfLoadImage row holds, shiftIdImage row]
    cases load : row.isHalfLoad with
    | false => exact mulLeftZero (mulLeftZero bitFalse)
    | true =>
        rcases holds.halfShiftId (halfOfHalfLoad load) with shift | shift
        · exact mulRightZero (limbSub (holds.halfLoadLow load shift).1)
        · exact mulLeftZero (mulRightZero (lowHalfNil shift))
  · rw [halfLoadImage row holds, shiftIdImage row]
    cases load : row.isHalfLoad with
    | false => exact mulLeftZero (mulLeftZero bitFalse)
    | true =>
        rcases holds.halfShiftId (halfOfHalfLoad load) with shift | shift
        · exact mulRightZero (limbSub (holds.halfLoadLow load shift).2)
        · exact mulLeftZero (mulRightZero (lowHalfNil shift))
  · rw [halfLoadImage row holds, shiftIdImage row]
    cases load : row.isHalfLoad with
    | false => exact mulLeftZero (mulLeftZero bitFalse)
    | true =>
        rcases holds.halfShiftId (halfOfHalfLoad load) with shift | shift
        · exact mulLeftZero (mulRightZero (highHalfNil shift))
        · exact mulRightZero (limbSub (holds.halfLoadHigh load shift).1)
  · rw [halfLoadImage row holds, shiftIdImage row]
    cases load : row.isHalfLoad with
    | false => exact mulLeftZero (mulLeftZero bitFalse)
    | true =>
        rcases holds.halfShiftId (halfOfHalfLoad load) with shift | shift
        · exact mulLeftZero (mulRightZero (highHalfNil shift))
        · exact mulRightZero (limbSub (holds.halfLoadHigh load shift).2)
  -- C38-C41: half-word store placement
  · rw [shiftIdImage row]
    cases store : row.isSh with
    | false => exact mulLeftZero (mulLeftZero bitFalse)
    | true =>
        rcases holds.halfShiftId (halfOfStoreHalf store) with shift | shift
        · exact mulRightZero (limbSub (holds.halfStoreLow store shift).1)
        · exact mulLeftZero (mulRightZero (lowHalfNil shift))
  · rw [shiftIdImage row]
    cases store : row.isSh with
    | false => exact mulLeftZero (mulLeftZero bitFalse)
    | true =>
        rcases holds.halfShiftId (halfOfStoreHalf store) with shift | shift
        · exact mulRightZero (limbSub (holds.halfStoreLow store shift).2)
        · exact mulLeftZero (mulRightZero (lowHalfNil shift))
  · rw [shiftIdImage row]
    cases store : row.isSh with
    | false => exact mulLeftZero (mulLeftZero bitFalse)
    | true =>
        rcases holds.halfShiftId (halfOfStoreHalf store) with shift | shift
        · exact mulLeftZero (mulRightZero (highHalfNil shift))
        · exact mulRightZero (limbSub (holds.halfStoreHigh store shift).1)
  · rw [shiftIdImage row]
    cases store : row.isSh with
    | false => exact mulLeftZero (mulLeftZero bitFalse)
    | true =>
        rcases holds.halfShiftId (halfOfStoreHalf store) with shift | shift
        · exact mulLeftZero (mulRightZero (highHalfNil shift))
        · exact mulRightZero (limbSub (holds.halfStoreHigh store shift).2)
  -- C42-C45: the word-width branch, load and store in one root
  · rcases wordCases row holds with ⟨lw, sw⟩ | ⟨lw, sw⟩ | ⟨lw, sw⟩
    · exact addZeros (by rw [lw]; exact mulLeftZero bitFalse)
        (by rw [sw]; exact mulLeftZero bitFalse)
    · exact addZeros (by rw [holds.wordLoad lw]; exact mulRightZero (M31.sub_self _))
        (by rw [sw]; exact mulLeftZero bitFalse)
    · exact addZeros (by rw [lw]; exact mulLeftZero bitFalse)
        (by rw [holds.wordStore sw]; exact mulRightZero (M31.sub_self _))
  · rcases wordCases row holds with ⟨lw, sw⟩ | ⟨lw, sw⟩ | ⟨lw, sw⟩
    · exact addZeros (by rw [lw]; exact mulLeftZero bitFalse)
        (by rw [sw]; exact mulLeftZero bitFalse)
    · exact addZeros (by rw [holds.wordLoad lw]; exact mulRightZero (M31.sub_self _))
        (by rw [sw]; exact mulLeftZero bitFalse)
    · exact addZeros (by rw [lw]; exact mulLeftZero bitFalse)
        (by rw [holds.wordStore sw]; exact mulRightZero (M31.sub_self _))
  · rcases wordCases row holds with ⟨lw, sw⟩ | ⟨lw, sw⟩ | ⟨lw, sw⟩
    · exact addZeros (by rw [lw]; exact mulLeftZero bitFalse)
        (by rw [sw]; exact mulLeftZero bitFalse)
    · exact addZeros (by rw [holds.wordLoad lw]; exact mulRightZero (M31.sub_self _))
        (by rw [sw]; exact mulLeftZero bitFalse)
    · exact addZeros (by rw [lw]; exact mulLeftZero bitFalse)
        (by rw [holds.wordStore sw]; exact mulRightZero (M31.sub_self _))
  · rcases wordCases row holds with ⟨lw, sw⟩ | ⟨lw, sw⟩ | ⟨lw, sw⟩
    · exact addZeros (by rw [lw]; exact mulLeftZero bitFalse)
        (by rw [sw]; exact mulLeftZero bitFalse)
    · exact addZeros (by rw [holds.wordLoad lw]; exact mulRightZero (M31.sub_self _))
        (by rw [sw]; exact mulLeftZero bitFalse)
    · exact addZeros (by rw [lw]; exact mulLeftZero bitFalse)
        (by rw [holds.wordStore sw]; exact mulRightZero (M31.sub_self _))
  -- C46-C49: an unmarked byte of a partial store survives
  · cases mark : row.marker0 with
    | true => exact mulLeftZero (mulRightZero oneSubBitTrue)
    | false =>
        cases sb : row.isSb with
        | true => exact mulRightZero (limbSub
            ((holds.partialStorePreserve (Or.inl sb)).1 mark))
        | false =>
            cases sh : row.isSh with
            | true => exact mulRightZero (limbSub
                ((holds.partialStorePreserve (Or.inr sh)).1 mark))
            | false => exact mulLeftZero (mulLeftZero bitFalseSum)
  · cases mark : row.marker1 with
    | true => exact mulLeftZero (mulRightZero oneSubBitTrue)
    | false =>
        cases sb : row.isSb with
        | true => exact mulRightZero (limbSub
            ((holds.partialStorePreserve (Or.inl sb)).2.1 mark))
        | false =>
            cases sh : row.isSh with
            | true => exact mulRightZero (limbSub
                ((holds.partialStorePreserve (Or.inr sh)).2.1 mark))
            | false => exact mulLeftZero (mulLeftZero bitFalseSum)
  · cases mark : row.marker2 with
    | true => exact mulLeftZero (mulRightZero oneSubBitTrue)
    | false =>
        cases sb : row.isSb with
        | true => exact mulRightZero (limbSub
            ((holds.partialStorePreserve (Or.inl sb)).2.2.1 mark))
        | false =>
            cases sh : row.isSh with
            | true => exact mulRightZero (limbSub
                ((holds.partialStorePreserve (Or.inr sh)).2.2.1 mark))
            | false => exact mulLeftZero (mulLeftZero bitFalseSum)
  · cases mark : row.marker3 with
    | true => exact mulLeftZero (mulRightZero oneSubBitTrue)
    | false =>
        cases sb : row.isSb with
        | true => exact mulRightZero (limbSub
            ((holds.partialStorePreserve (Or.inl sb)).2.2.2 mark))
        | false =>
            cases sh : row.isSh with
            | true => exact mulRightZero (limbSub
                ((holds.partialStorePreserve (Or.inr sh)).2.2.2 mark))
            | false => exact mulLeftZero (mulLeftZero bitFalseSum)
  -- C50: booleanity of the destination witness
  · exact bitBooleanVanishes row.destinationNonzero
  -- C51: r2_idx * (1 - destination_nonzero)
  · cases nonzero : row.destinationNonzero with
    | true => exact mulRightZero oneSubBitTrue
    | false =>
        have image := r2NonzeroImage row holds
        rw [nonzero] at image
        have zero : row.r2Idx.toNat = 0 := by simpa using image.symm
        rw [zero]
        exact mulLeftZero rfl
  -- C52: r2_idx * destination_inverse - destination_nonzero
  · have bound : row.r2Idx.toNat < 32 := by simpa using row.r2Idx.isLt
    rw [registerInverse, M31.reduce_mul, r2NonzeroImage row holds,
      bitValue_eq_flagValue]
    exact M31.reduce_sub_eq_zero _ _ (registerInverseTable_spec row.r2Idx.toNat bound)
  -- C53-C56: is_load * (dst_next_i - destination_nonzero * result_i)
  · rw [activeImage row holds, storeImage row holds, loadImage row]
    cases direction : row.isLoad with
    | false => exact mulLeftZero bitFalse
    | true =>
        refine mulRightZero (loadDestinationVanishes ?_)
        cases nonzero : row.destinationNonzero <;>
          simp [holds.loadDestination direction, nonzero, WordBytes.zero]
  · rw [activeImage row holds, storeImage row holds, loadImage row]
    cases direction : row.isLoad with
    | false => exact mulLeftZero bitFalse
    | true =>
        refine mulRightZero (loadDestinationVanishes ?_)
        cases nonzero : row.destinationNonzero <;>
          simp [holds.loadDestination direction, nonzero, WordBytes.zero]
  · rw [activeImage row holds, storeImage row holds, loadImage row]
    cases direction : row.isLoad with
    | false => exact mulLeftZero bitFalse
    | true =>
        refine mulRightZero (loadDestinationVanishes ?_)
        cases nonzero : row.destinationNonzero <;>
          simp [holds.loadDestination direction, nonzero, WordBytes.zero]
  · rw [activeImage row holds, storeImage row holds, loadImage row]
    cases direction : row.isLoad with
    | false => exact mulLeftZero bitFalse
    | true =>
        refine mulRightZero (loadDestinationVanishes ?_)
        cases nonzero : row.destinationNonzero <;>
          simp [holds.loadDestination direction, nonzero, WordBytes.zero]
  -- C57-C60: a store writes no architectural result
  · rw [activeImage row holds, storeImage row holds, loadImage row]
    cases direction : row.isLoad with
    | true => exact mulLeftZero oneSubBitTrue
    | false => rw [holds.storeResultZero (storeOfNotLoad direction)]
               exact mulRightZero rfl
  · rw [activeImage row holds, storeImage row holds, loadImage row]
    cases direction : row.isLoad with
    | true => exact mulLeftZero oneSubBitTrue
    | false => rw [holds.storeResultZero (storeOfNotLoad direction)]
               exact mulRightZero rfl
  · rw [activeImage row holds, storeImage row holds, loadImage row]
    cases direction : row.isLoad with
    | true => exact mulLeftZero oneSubBitTrue
    | false => rw [holds.storeResultZero (storeOfNotLoad direction)]
               exact mulRightZero rfl
  · rw [activeImage row holds, storeImage row holds, loadImage row]
    cases direction : row.isLoad with
    | true => exact mulLeftZero oneSubBitTrue
    | false => rw [holds.storeResultZero (storeOfNotLoad direction)]
               exact mulRightZero rfl
  -- C61: an active row's base register has a zero high byte
  · rw [activeImage row holds, holds.baseHighLimbZero]
    exact mulRightZero rfl
  -- C62: the placement residual, which pins the selector sum to one
  · rw [activeImage row holds]
    exact M31.sub_self 1

/-! ## The bridge for the fixed-table requests

This theorem carries the range-table half of the alignment discipline. C15 and
C20 constrain the byte offset for halfword and word accesses; lookup 6, the
`range_check_20` request on
`(src_addr_selector + dst_addr_selector - r2_idx) * 4⁻¹`. A request that lands
in the table certifies both that the aligned address is divisible by four and
that it is below `2 ^ 22`. A bridge stated over constraint roots alone would
miss that canonical aligned-bus bound. -/

/-- Every live fixed-table request the shipped `load_store` AIR makes lands
inside its table, for every row the transcription accepts.

"Live" means non-zero numerator, which is the LogUp reading: a term with a zero
numerator contributes nothing to the bus sum and is therefore not a request.
Only lookups 14 and 15 are ever dead, and only on rows that are neither `LB` nor
`LH`. See the counterexample `#guard` in `LoadStoreProgram.lean` — a satisfying
`LW` row whose lookup-14 tuple is `(0, 145)` — for why this cannot be
strengthened to the ungated reading. -/
theorem loadStoreFixedRequestsHold (row : LoadStoreRow) (holds : LoadStoreHolds row) :
    loadStoreCircuitCompiled.fixedRequestsHold (loadStoreColumns row) = true := by
  try simp only [LoadStoreRow.rs1Next, LoadStoreRow.srcNext] at holds
  have baseClock := holds.baseClock
  have sourceClock := sourceClockValid row holds
  have destinationClock := destinationClockValid row holds
  simp only [MulhCircuit.fixedRequestsHold, MulhCircuit.fixedRequestHolds,
    MulhCircuit.lookupTuple, MulhCircuit.lookupNumerator, MulhCircuit.values,
    MulhCircuit.value, MulhCircuit.nodeValuesRev, loadStoreCircuitCompiled,
    loadStoreCircuit, evalLoop, Node.evalLocal, nth, List.map_cons, List.map_nil,
    List.all_cons, List.all_nil, loadStoreColumns, rangeCheck20Contains,
    rangeCheckM31Contains, Bool.or_true, Bool.and_true]
  simp only [Bool.and_eq_true, Bool.or_eq_true, Bool.true_and,
    Bool.not_eq_eq_eq_not, Bool.not_true, decide_eq_true_eq]
  rw [activeImage row holds, storeImage row holds, loadImage row,
    baseGapImage row holds, sourceGapImage row holds, destinationGapImage row holds,
    alignedQuarterImage row]
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  -- L05: the base register access-clock gap
  · exact Or.inr (reduceToNat_lt baseClock.2)
  -- L06: the aligned address divided by four, which is what forces alignment
  · exact Or.inr (reduceToNat_lt holds.alignedQuarterRange)
  -- L07: the base address stays canonical
  · refine Or.inr ⟨⟨reduceToNat_lt ?_, reduceToNat_lt holds.baseHighLimbRange⟩, ?_⟩
    · simpa using row.rs1Previous.limb0.isLt
    · have canonical0 : (M31.reduce row.rs1Previous.limb0.toNat).toNat =
          row.rs1Previous.limb0.toNat := by
        refine M31.toNat_reduce_of_lt ?_
        have bound := row.rs1Previous.limb0.isLt
        simp only [Nat.reducePow] at bound
        simp only [M31.modulus, RiscvRefinement.Air.Bridge.m31Modulus]
        omega
      have canonical3 : (M31.reduce row.rs1Previous.limb3.toNat).toNat =
          row.rs1Previous.limb3.toNat := by
        refine M31.toNat_reduce_of_lt ?_
        have bound := row.rs1Previous.limb3.isLt
        simp only [Nat.reducePow] at bound
        simp only [M31.modulus, RiscvRefinement.Air.Bridge.m31Modulus]
        omega
      rw [canonical0, canonical3]
      rcases holds.baseLimbsCanonical with low | high
      · rw [decide_eq_false low, Bool.false_and]
      · rw [decide_eq_false high, Bool.and_false]
  -- L10: the source access-clock gap
  · exact Or.inr (reduceToNat_lt sourceClock.2)
  -- L13: the destination access-clock gap
  · exact Or.inr (reduceToNat_lt destinationClock.2)
  -- L14: the byte sign witness, live only on an `LB` row
  · cases byteLoad : row.isLb with
    | false => exact Or.inl rfl
    | true =>
        refine Or.inr ⟨⟨by decide, ?_⟩, zeroNotReserved _⟩
        rw [(msbResidue row.result.limb0 row.srcMsb (holds.byteSignWitness byteLoad)).1]
        exact reduceToNat_lt
          (msbResidue row.result.limb0 row.srcMsb (holds.byteSignWitness byteLoad)).2
  -- L15: the half-word sign witness, live only on an `LH` row
  · cases halfLoad : row.isLh with
    | false => exact Or.inl rfl
    | true =>
        refine Or.inr ⟨⟨by decide, ?_⟩, zeroNotReserved _⟩
        rw [(msbResidue row.result.limb1 row.srcMsb (holds.halfSignWitness halfLoad)).1]
        exact reduceToNat_lt
          (msbResidue row.result.limb1 row.srcMsb (holds.halfSignWitness halfLoad)).2

/-! ## The bridge for the relation arguments

The sixteen lookup tuples the shipped AIR emits, evaluated under the same
column assignment. This is the statement that the relation arguments Team B
writes down in `loadStoreRelations` — the program tuple, the two state tuples,
the six `memory_access` tuples — are the tuples the production AIR actually puts
on the bus, rather than a parallel description of them.

The two `memory_access` blocks are the interesting part and are stated exactly
as the AIR spells them: the address space of the `src` block is `is_load` and
of the `dst` block is `is_store`, so on a load the `src` triple is a data-memory
access and the `dst` triple a register access, and on a store the two swap.
`loadStoreLoadMemoryAccess` and `loadStoreStoreMemoryAccess` below read that
back off in the transcription's vocabulary. -/

theorem loadStoreLookupTuples (row : LoadStoreRow) (holds : LoadStoreHolds row)
    (fits : LoadStoreRowFits row) :
    loadStoreCircuitCompiled.lookups.map
        (loadStoreCircuitCompiled.lookupTuple (loadStoreColumns row)) =
      [ -- 0  program_access request
        [M31.reduce row.pc.toNat, M31.reduce row.opcodeId,
          M31.reduce row.rs1Addr.toNat, M31.reduce row.r2Idx.toNat,
          M31.reduce row.immFelt],
        -- 1  registers_state consume
        [M31.reduce row.pc.toNat, M31.reduce row.clock],
        -- 2  registers_state emit
        [M31.reduce row.claimedNextPc.toNat, M31.reduce (row.clock + 1)],
        -- 3  rs1 register consume, address space 0
        [M31.reduce 0, M31.reduce row.rs1Addr.toNat,
          M31.reduce row.rs1PreviousClock,
          M31.reduce row.rs1Previous.limb0.toNat,
          M31.reduce row.rs1Previous.limb1.toNat,
          M31.reduce row.rs1Previous.limb2.toNat,
          M31.reduce row.rs1Previous.limb3.toNat],
        -- 4  rs1 register emit, address space 0, ordinal one
        [M31.reduce 0, M31.reduce row.rs1Addr.toNat,
          M31.reduce (accessClock row.clock 1),
          M31.reduce row.rs1Previous.limb0.toNat,
          M31.reduce row.rs1Previous.limb1.toNat,
          M31.reduce row.rs1Previous.limb2.toNat,
          M31.reduce row.rs1Previous.limb3.toNat],
        -- 5  rs1 access-clock gap
        [M31.reduce (accessClock row.clock 1 - row.rs1PreviousClock - 1)],
        -- 6  the aligned word address divided by four
        [M31.reduce row.alignedQuarter],
        -- 7  the base address canonicity request
        [M31.reduce row.rs1Previous.limb0.toNat, M31.reduce row.rs1Previous.limb3.toNat],
        -- 8  src block consume, address space `is_load`
        [M31.reduce (bitValue row.isLoad), M31.reduce row.sourceSelector,
          M31.reduce row.srcPreviousClock,
          M31.reduce row.srcPrevious.limb0.toNat,
          M31.reduce row.srcPrevious.limb1.toNat,
          M31.reduce row.srcPrevious.limb2.toNat,
          M31.reduce row.srcPrevious.limb3.toNat],
        -- 9  src block emit
        [M31.reduce (bitValue row.isLoad), M31.reduce row.sourceSelector,
          M31.reduce (sourceAccessClock row),
          M31.reduce row.srcPrevious.limb0.toNat,
          M31.reduce row.srcPrevious.limb1.toNat,
          M31.reduce row.srcPrevious.limb2.toNat,
          M31.reduce row.srcPrevious.limb3.toNat],
        -- 10 src access-clock gap
        [M31.reduce (sourceAccessClock row - row.srcPreviousClock - 1)],
        -- 11 dst block consume, address space `is_store`
        [M31.reduce (bitValue row.isStore), M31.reduce row.destinationSelector,
          M31.reduce row.dstPreviousClock,
          M31.reduce row.dstPrevious.limb0.toNat,
          M31.reduce row.dstPrevious.limb1.toNat,
          M31.reduce row.dstPrevious.limb2.toNat,
          M31.reduce row.dstPrevious.limb3.toNat],
        -- 12 dst block emit
        [M31.reduce (bitValue row.isStore), M31.reduce row.destinationSelector,
          M31.reduce (destinationAccessClock row),
          M31.reduce row.dstNext.limb0.toNat,
          M31.reduce row.dstNext.limb1.toNat,
          M31.reduce row.dstNext.limb2.toNat,
          M31.reduce row.dstNext.limb3.toNat],
        -- 13 dst access-clock gap
        [M31.reduce (destinationAccessClock row - row.dstPreviousClock - 1)],
        -- 14 the byte sign witness residue
        [M31.reduce 0,
          M31.reduce row.result.limb0.toNat -
            M31.reduce (bitValue row.srcMsb) * M31.reduce 128],
        -- 15 the half-word sign witness residue
        [M31.reduce 0,
          M31.reduce row.result.limb1.toNat -
            M31.reduce (bitValue row.srcMsb) * M31.reduce 128] ] := by
  try simp only [LoadStoreRow.rs1Next, LoadStoreRow.srcNext] at holds
  simp only [MulhCircuit.lookupTuple, MulhCircuit.values, MulhCircuit.value,
    MulhCircuit.nodeValuesRev, loadStoreCircuitCompiled, loadStoreCircuit, evalLoop,
    Node.evalLocal, nth, List.map_cons, List.map_nil, loadStoreColumns]
  rw [activeImage row holds, storeImage row holds, loadImage row,
    opcodeImage row holds, baseGapImage row holds, sourceGapImage row holds,
    destinationGapImage row holds, accessClockImage row holds 1,
    sourceAccessClockImage row holds, destinationAccessClockImage row holds,
    alignedQuarterImage row, nextPcImage row holds fits, M31.reduce_add,
    M31.reduce_add]

/-! ## Reading the address-space swap back in the transcription's vocabulary

`loadStoreLookupTuples` states the two swapping access blocks exactly as the AIR
does — space `is_load` for `src` and `is_store` for `dst`. These two corollaries
say what that means: on a load the AIR's `src` triple is the *data memory*
access of `loadStoreRelations` at ordinal three and its `dst` triple is the
`r2_idx` *register* access at ordinal two, and on a store the two swap. Without
them "the AIR's tuples are `loadStoreRelations`'s tuples" would be an eyeball
claim about which committed block is which. -/

theorem loadStoreLoadMemoryAccess (row : LoadStoreRow) (holds : LoadStoreHolds row)
    (direction : row.isStore = false) :
    bitValue row.isLoad = 1 ∧ bitValue row.isStore = 0 ∧
      row.sourceSelector = (loadStoreRelations row).memoryConsume.addr.toNat ∧
      sourceAccessClock row = (loadStoreRelations row).memoryEmit.clock ∧
      row.destinationSelector = (loadStoreRelations row).operandEmit.addr.toNat ∧
      destinationAccessClock row = (loadStoreRelations row).operandEmit.clock := by
  have aligned := alignedAddressSmall row holds
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_⟩
  · simp [LoadStoreRow.isLoad, direction]
  · simp [direction]
  · simp [LoadStoreRow.sourceSelector, direction, loadStoreRelations,
      LoadStoreRow.busAddress]
    omega
  · rw [sourceAccessClock_load row direction]
    simp [loadStoreRelations]
  · simp [LoadStoreRow.destinationSelector, direction, loadStoreRelations]
  · rw [destinationAccessClock_load row direction]
    simp [loadStoreRelations]

theorem loadStoreStoreMemoryAccess (row : LoadStoreRow) (holds : LoadStoreHolds row)
    (direction : row.isStore = true) :
    bitValue row.isLoad = 0 ∧ bitValue row.isStore = 1 ∧
      row.destinationSelector = (loadStoreRelations row).memoryConsume.addr.toNat ∧
      destinationAccessClock row = (loadStoreRelations row).memoryEmit.clock ∧
      row.sourceSelector = (loadStoreRelations row).operandEmit.addr.toNat ∧
      sourceAccessClock row = (loadStoreRelations row).operandEmit.clock := by
  have aligned := alignedAddressSmall row holds
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_⟩
  · simp [LoadStoreRow.isLoad, direction]
  · simp [direction]
  · simp [LoadStoreRow.destinationSelector, direction, loadStoreRelations,
      LoadStoreRow.busAddress]
    omega
  · rw [destinationAccessClock_store row direction]
    simp [loadStoreRelations]
  · simp [LoadStoreRow.sourceSelector, direction, loadStoreRelations]
  · rw [sourceAccessClock_store row direction]
    simp [loadStoreRelations]

/-! ## Non-vacuity, and a check on the column assignment itself

`loadStoreColumns` is hand-written, so it is exactly the kind of transcription
this work exists to remove. It is checked here against the two witness column
vectors the generator computed independently from `load_store.json` (and which
the generated file already checks satisfy every constraint root and every live
table request). If a column were mis-ordered or mis-populated, these `#guard`s
fail. Both directions are exercised, because every gate in this family is a
conditional on `is_store`. -/

/-- `LW x7, 0(x1)` with `x1 = 64` and the word `0x44332291` at address 64. Its
`result_0` is `145`, which is *not* a seven-bit value — that is what makes the
dead lookup-14 request in `LoadStoreProgram.lean` a real counterexample to the
ungated reading of `fixedRequestsHold`. -/
def loadStoreLoadWitnessRow : LoadStoreRow where
  clock := 5
  pc := 100#32
  dstPrevious := { limb0 := 0#8, limb1 := 0#8, limb2 := 0#8, limb3 := 0#8 }
  dstPreviousClock := 3
  dstNext := { limb0 := 145#8, limb1 := 34#8, limb2 := 51#8, limb3 := 68#8 }
  rs1Addr := 1#5
  rs1Previous := { limb0 := 64#8, limb1 := 0#8, limb2 := 0#8, limb3 := 0#8 }
  rs1PreviousClock := 3
  srcPrevious := { limb0 := 145#8, limb1 := 34#8, limb2 := 51#8, limb3 := 68#8 }
  srcPreviousClock := 3
  r2Idx := 7#5
  immFelt := 0
  srcMsb := false
  shiftAmount := 0
  alignedQuarter := 16
  marker0 := false
  marker1 := false
  marker2 := false
  marker3 := false
  isLb := false
  isLh := false
  isLbu := false
  isLhu := false
  isLw := true
  isSb := false
  isSh := false
  isSw := false
  result := { limb0 := 145#8, limb1 := 34#8, limb2 := 51#8, limb3 := 68#8 }
  destinationNonzero := true

/-- `SB x2, 1(x1)` with `x1 = 65`, `x2 = 0xab` and `0x44332211` at address 64.
Marker 1 is hot, so the store is a genuinely partial one: bytes 0, 2 and 3 of
the destination word survive by C54–C57. -/
def loadStoreStoreWitnessRow : LoadStoreRow where
  clock := 5
  pc := 200#32
  dstPrevious := { limb0 := 17#8, limb1 := 34#8, limb2 := 51#8, limb3 := 68#8 }
  dstPreviousClock := 3
  dstNext := { limb0 := 17#8, limb1 := 171#8, limb2 := 51#8, limb3 := 68#8 }
  rs1Addr := 1#5
  rs1Previous := { limb0 := 65#8, limb1 := 0#8, limb2 := 0#8, limb3 := 0#8 }
  rs1PreviousClock := 3
  srcPrevious := { limb0 := 171#8, limb1 := 0#8, limb2 := 0#8, limb3 := 0#8 }
  srcPreviousClock := 3
  r2Idx := 2#5
  immFelt := 0
  srcMsb := false
  shiftAmount := 1
  alignedQuarter := 16
  marker0 := false
  marker1 := true
  marker2 := false
  marker3 := false
  isLb := false
  isLh := false
  isLbu := false
  isLhu := false
  isLw := false
  isSb := true
  isSh := false
  isSw := false
  result := WordBytes.zero
  destinationNonzero := true

#guard loadStoreColumns loadStoreLoadWitnessRow == loadStoreLoadWitnessColumns

#guard loadStoreColumns loadStoreStoreWitnessRow == loadStoreStoreWitnessColumns

-- Columns 2 (`dst_addr`) and 18 (`src_addr`) are assigned zero above on the
-- grounds that the shipped AIR never reads them. That is checked, not asserted:
-- perturbing exactly those two entries of a satisfying column vector changes
-- neither the 63 constraint values nor any of the 16 lookup tuples. If a future
-- export started reading either column, these two `#guard`s would fail before
-- the zero assignment could quietly weaken anything.
def loadStoreDeadColumnsPerturbed : List M31 :=
  (loadStoreLoadWitnessColumns.set 2 (M31.reduce 1234567)).set 18 (M31.reduce 7654321)

#guard loadStoreCircuitCompiled.constraintValues loadStoreDeadColumnsPerturbed ==
  loadStoreCircuitCompiled.constraintValues loadStoreLoadWitnessColumns

#guard (loadStoreCircuitCompiled.lookups.map
      (loadStoreCircuitCompiled.lookupTuple loadStoreDeadColumnsPerturbed)) ==
  (loadStoreCircuitCompiled.lookups.map
      (loadStoreCircuitCompiled.lookupTuple loadStoreLoadWitnessColumns))

theorem loadStoreLoadWitnessHolds : LoadStoreHolds loadStoreLoadWitnessRow := by
  constructor <;> first
    | decide
    | exact ⟨by decide, by decide⟩

theorem loadStoreLoadWitnessFits : LoadStoreRowFits loadStoreLoadWitnessRow := by
  constructor
  decide

theorem loadStoreStoreWitnessHolds : LoadStoreHolds loadStoreStoreWitnessRow := by
  constructor <;> first
    | decide
    | exact ⟨by decide, by decide⟩

theorem loadStoreStoreWitnessFits : LoadStoreRowFits loadStoreStoreWitnessRow := by
  constructor
  decide

-- The bridge is therefore not vacuous in either direction: both rows satisfy
-- every hypothesis of all three theorems.
theorem loadStoreLoadWitnessConstraintValues :
    loadStoreCircuitCompiled.constraintValues (loadStoreColumns loadStoreLoadWitnessRow) =
      List.replicate 63 0 :=
  loadStoreConstraintValues loadStoreLoadWitnessRow loadStoreLoadWitnessHolds
    loadStoreLoadWitnessFits

theorem loadStoreStoreWitnessConstraintValues :
    loadStoreCircuitCompiled.constraintValues (loadStoreColumns loadStoreStoreWitnessRow) =
      List.replicate 63 0 :=
  loadStoreConstraintValues loadStoreStoreWitnessRow loadStoreStoreWitnessHolds
    loadStoreStoreWitnessFits

theorem loadStoreLoadWitnessFixedRequestsHold :
    loadStoreCircuitCompiled.fixedRequestsHold (loadStoreColumns loadStoreLoadWitnessRow) =
      true :=
  loadStoreFixedRequestsHold loadStoreLoadWitnessRow loadStoreLoadWitnessHolds

theorem loadStoreStoreWitnessFixedRequestsHold :
    loadStoreCircuitCompiled.fixedRequestsHold (loadStoreColumns loadStoreStoreWitnessRow) =
      true :=
  loadStoreFixedRequestsHold loadStoreStoreWitnessRow loadStoreStoreWitnessHolds

-- The gate on `loadStoreFixedRequestsHold` is load-bearing. On the `LW`
-- witness the *ungated* reading is false -- lookup 14's tuple is `(0, 145)` and
-- `145` is not a seven-bit value -- so the theorem above cannot be strengthened
-- to it. Deleting the gate would require deleting this `#guard` first.
#guard !loadStoreCircuitCompiled.fixedRequestsHoldUnconditional
    (loadStoreColumns loadStoreLoadWitnessRow)

end RiscvRefinement.Air.Bridge
