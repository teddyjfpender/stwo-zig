-- The AIR-interpreter bridge for the `load_store` family: `LB`, `LH`, `LW`,
-- `LBU`, `LHU`, `SB`, `SH`, `SW`.
--
-- Third family bridged this way, after `Air/Bridge/MulBridge.lean` (22 roots)
-- and `Air/Bridge/MulhBridge.lean` (30 roots). Issue #137 forbids Team B from
-- restating production constraints in a private Lean predicate, and
-- `RiscvRefinement/Air/Family/LoadStore.lean` currently does exactly that:
-- `LoadStoreHolds` is a hand transcription of `/tmp/tb-ir/load_store.json`.
-- This file maps a typed `LoadStoreRow` onto the 64 columns of the shipped AIR
-- and proves, by *evaluating the encoded production node table*, that whenever
-- `LoadStoreHolds row` holds
--
--   * every one of the 78 constraint roots evaluates to zero,
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

-- The encoded node table and the hand transcription in
-- `Air/Family/LoadStore.lean` are pinned to the same export.
-- `loadStoreProgramIrDigest` is written by the generator from the sha256 of the
-- bytes it read; `loadStoreIrDigest` is the constant the transcription carries.
#guard loadStoreProgramIrDigest == loadStoreIrDigest

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

theorem reduce_one : M31.reduce 1 = 1 := rfl

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

/-- `1 - b` vanishes when the bit is set. -/
private theorem oneSubBit_of_true {flag : Bool} (set : flag = true) :
    M31.reduce 1 - M31.reduce (bitValue flag) = 0 := by
  rw [set]
  exact M31.sub_self 1

/-- The image of a clear bit is zero. -/
private theorem bitZero {flag : Bool} (clear : flag = false) :
    M31.reduce (bitValue flag) = 0 := by
  rw [clear]
  rfl

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

* `dst_addr` (column 2) and `src_addr` (column 22) are **dead** in the shipped
  AIR — no node reads either of them, which the generated file records — so
  they are assigned zero. The live addresses are `src_addr_selector` and
  `dst_addr_selector`, columns 36 and 37, and those are the derived selectors
  `LoadStoreRow.sourceSelector` / `destinationSelector` that C16 and C17 define.
* `destination_inverse` (column 55) is the `M31` inverse of `r2_idx`, taken
  from the same 32-entry table `MulBridge.lean` uses.
* the eight `bus_value_*` columns (56–63) are the materialised opcode id, next
  pc, next clock and three access clocks. -/

/-- The typed row, laid out as the 64 columns of `load_store.json`. -/
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
    M31.reduce row.rs1Next.limb0.toNat,            -- 18 rs1_next_0
    M31.reduce row.rs1Next.limb1.toNat,            -- 19 rs1_next_1
    M31.reduce row.rs1Next.limb2.toNat,            -- 20 rs1_next_2
    M31.reduce row.rs1Next.limb3.toNat,            -- 21 rs1_next_3
    M31.reduce 0,                                  -- 22 src_addr (dead)
    M31.reduce row.srcPrevious.limb0.toNat,        -- 23 src_previous_0
    M31.reduce row.srcPrevious.limb1.toNat,        -- 24 src_previous_1
    M31.reduce row.srcPrevious.limb2.toNat,        -- 25 src_previous_2
    M31.reduce row.srcPrevious.limb3.toNat,        -- 26 src_previous_3
    M31.reduce row.srcPreviousClock,               -- 27 src_previous_clock
    M31.reduce row.srcNext.limb0.toNat,            -- 28 src_next_0
    M31.reduce row.srcNext.limb1.toNat,            -- 29 src_next_1
    M31.reduce row.srcNext.limb2.toNat,            -- 30 src_next_2
    M31.reduce row.srcNext.limb3.toNat,            -- 31 src_next_3
    M31.reduce row.r2Idx.toNat,                    -- 32 r2_idx
    M31.reduce row.immFelt,                        -- 33 imm_felt
    M31.reduce (bitValue row.srcMsb),              -- 34 src_msb
    M31.reduce row.shiftAmount,                    -- 35 shift_amount
    M31.reduce row.sourceSelector,                 -- 36 src_addr_selector
    M31.reduce row.destinationSelector,            -- 37 dst_addr_selector
    M31.reduce (bitValue row.marker0),             -- 38 markers_0
    M31.reduce (bitValue row.marker1),             -- 39 markers_1
    M31.reduce (bitValue row.marker2),             -- 40 markers_2
    M31.reduce (bitValue row.marker3),             -- 41 markers_3
    M31.reduce (bitValue row.isLb),                -- 42 is_lb
    M31.reduce (bitValue row.isLh),                -- 43 is_lh
    M31.reduce (bitValue row.isLbu),               -- 44 is_lbu
    M31.reduce (bitValue row.isLhu),               -- 45 is_lhu
    M31.reduce (bitValue row.isLw),                -- 46 is_lw
    M31.reduce (bitValue row.isSb),                -- 47 is_sb
    M31.reduce (bitValue row.isSh),                -- 48 is_sh
    M31.reduce (bitValue row.isSw),                -- 49 is_sw
    M31.reduce row.result.limb0.toNat,             -- 50 result_0
    M31.reduce row.result.limb1.toNat,             -- 51 result_1
    M31.reduce row.result.limb2.toNat,             -- 52 result_2
    M31.reduce row.result.limb3.toNat,             -- 53 result_3
    M31.reduce (bitValue row.destinationNonzero),  -- 54 destination_nonzero
    registerInverse row.r2Idx,                     -- 55 destination_inverse
    M31.reduce row.opcodeId,                       -- 56 bus_value_56
    M31.reduce row.claimedNextPc.toNat,            -- 57 bus_value_57
    M31.reduce (row.clock + 1),                    -- 58 bus_value_58
    M31.reduce (accessClock row.clock 1),          -- 59 bus_value_59
    M31.reduce (bitValue row.isLoad),              -- 60 bus_value_60
    M31.reduce (sourceAccessClock row),            -- 61 bus_value_61
    M31.reduce (bitValue row.isStore),             -- 62 bus_value_62
    M31.reduce (destinationAccessClock row) ]      -- 63 bus_value_63

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
    ((M31.reduce row.rs1Next.limb3.toNat * M31.reduce 256 +
                M31.reduce row.rs1Next.limb2.toNat) * M31.reduce 256 +
              M31.reduce row.rs1Next.limb1.toNat) * M31.reduce 256 +
          M31.reduce row.rs1Next.limb0.toNat +
        M31.reduce row.immFelt -
      M31.reduce row.shiftAmount =
    M31.reduce row.alignedAddress := by
  have small := shiftAmountSmall row holds
  have aligned := alignedAddressSmall row holds
  have address : (row.rs1Next.value + row.immFelt) % M31.modulus =
      row.alignedAddress + row.shiftAmount := holds.memoryAddress
  simp only [M31.reduce_mul, M31.reduce_add]
  have compose :
      ((row.rs1Next.limb3.toNat * 256 + row.rs1Next.limb2.toNat) * 256 +
                row.rs1Next.limb1.toNat) * 256 + row.rs1Next.limb0.toNat +
            row.immFelt =
          row.rs1Next.value + row.immFelt := by
    simp only [WordBytes.value]
    omega
  rw [compose]
  have canonical : M31.reduce (row.rs1Next.value + row.immFelt) =
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
  simp only [holds.nextPcResult, RiscvRefinement.nextPc, BitVec.toNat_add,
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

/-! ## The bridge for the constraint roots

The proof has one shape: unfold the encoded node table under the column
assignment — this *is* the evaluation of the production AIR — and discharge the
78 resulting `M31` identities from `LoadStoreHolds`. -/

/-- Every constraint root of the encoded production `load_store` AIR evaluates
to zero under `loadStoreColumns row`, for every row the transcription accepts. -/
theorem loadStoreConstraintValues (row : LoadStoreRow) (holds : LoadStoreHolds row)
    (fits : LoadStoreRowFits row) :
    loadStoreCircuitCompiled.constraintValues (loadStoreColumns row) =
      List.replicate 78 0 := by
  simp only [MulhCircuit.constraintValues, MulhCircuit.values, MulhCircuit.value,
    MulhCircuit.nodeValuesRev, loadStoreCircuitCompiled, loadStoreCircuit, evalLoop,
    Node.evalLocal, nth, List.map_cons, List.map_nil, loadStoreColumns, List.replicate,
    List.cons.injEq, and_true]
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_,
    ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_,
    ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_,
    ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_,
    ?_, ?_, ?_, ?_⟩
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
  -- C46-C49: the base register access is read-only
  · rw [activeImage row holds]
    exact mulRightZero (limbSub (by rw [holds.baseReadOnly]))
  · rw [activeImage row holds]
    exact mulRightZero (limbSub (by rw [holds.baseReadOnly]))
  · rw [activeImage row holds]
    exact mulRightZero (limbSub (by rw [holds.baseReadOnly]))
  · rw [activeImage row holds]
    exact mulRightZero (limbSub (by rw [holds.baseReadOnly]))
  -- C50-C53: the source access is read-only
  · rw [activeImage row holds]
    exact mulRightZero (limbSub (by rw [holds.sourceReadOnly]))
  · rw [activeImage row holds]
    exact mulRightZero (limbSub (by rw [holds.sourceReadOnly]))
  · rw [activeImage row holds]
    exact mulRightZero (limbSub (by rw [holds.sourceReadOnly]))
  · rw [activeImage row holds]
    exact mulRightZero (limbSub (by rw [holds.sourceReadOnly]))
  -- C54-C57: an unmarked byte of a partial store survives
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
  -- C58: booleanity of the destination witness
  · exact bitBooleanVanishes row.destinationNonzero
  -- C59: r2_idx * (1 - destination_nonzero)
  · cases nonzero : row.destinationNonzero with
    | true => exact mulRightZero oneSubBitTrue
    | false =>
        have image := r2NonzeroImage row holds
        rw [nonzero] at image
        have zero : row.r2Idx.toNat = 0 := by simpa using image.symm
        rw [zero]
        exact mulLeftZero rfl
  -- C60: r2_idx * destination_inverse - destination_nonzero
  · have bound : row.r2Idx.toNat < 32 := by simpa using row.r2Idx.isLt
    rw [registerInverse, M31.reduce_mul, r2NonzeroImage row holds,
      bitValue_eq_flagValue]
    exact M31.reduce_sub_eq_zero _ _ (registerInverseTable_spec row.r2Idx.toNat bound)
  -- C61-C64: is_load * (dst_next_i - destination_nonzero * result_i)
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
  -- C65-C68: a store writes no architectural result
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
  -- C69: the placement residual, which pins the selector sum to one
  · rw [activeImage row holds]
    exact M31.sub_self 1
  -- C70: the materialised opcode identifier
  · rw [opcodeImage row holds]
    exact M31.sub_self _
  -- C71: bus_value_57 = pc + 4
  · rw [nextPcImage row holds fits, M31.reduce_add]
    exact M31.sub_self _
  -- C72: bus_value_58 = clk + 1
  · rw [M31.reduce_add]
    exact M31.sub_self _
  -- C73: bus_value_59 = accessClock(clk, 1)
  · rw [accessClockImage row holds 1]
    exact M31.sub_self _
  -- C74: bus_value_60 = is_load
  · rw [activeImage row holds, storeImage row holds, loadImage row]
    exact M31.sub_self _
  -- C75: bus_value_61 = accessClock(clk, 2) + is_load
  · rw [activeImage row holds, storeImage row holds, loadImage row,
      accessClockImage row holds 2, M31.reduce_add]
    exact M31.sub_self _
  -- C76: bus_value_62 = is_store
  · rw [storeImage row holds]
    exact M31.sub_self _
  -- C77: bus_value_63 = accessClock(clk, 2) + is_store
  · rw [storeImage row holds, accessClockImage row holds 2, M31.reduce_add]
    exact M31.sub_self _

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
  rs1Next := { limb0 := 64#8, limb1 := 0#8, limb2 := 0#8, limb3 := 0#8 }
  srcPrevious := { limb0 := 145#8, limb1 := 34#8, limb2 := 51#8, limb3 := 68#8 }
  srcPreviousClock := 3
  srcNext := { limb0 := 145#8, limb1 := 34#8, limb2 := 51#8, limb3 := 68#8 }
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
  claimedNextPc := 104#32

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
  rs1Next := { limb0 := 65#8, limb1 := 0#8, limb2 := 0#8, limb3 := 0#8 }
  srcPrevious := { limb0 := 171#8, limb1 := 0#8, limb2 := 0#8, limb3 := 0#8 }
  srcPreviousClock := 3
  srcNext := { limb0 := 171#8, limb1 := 0#8, limb2 := 0#8, limb3 := 0#8 }
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
  claimedNextPc := 204#32

#guard loadStoreColumns loadStoreLoadWitnessRow == loadStoreLoadWitnessColumns

#guard loadStoreColumns loadStoreStoreWitnessRow == loadStoreStoreWitnessColumns

end RiscvRefinement.Air.Bridge
