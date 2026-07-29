import RiscvRefinement.Memory

/-!
# `load_store` family AIR transcription

This file is a hand transcription of the **exported production symbolic AIR**
for the `load_store` family (`LB`, `LH`, `LW`, `LBU`, `LHU`, `SB`, `SH`, `SW`),
taken from `src/frontends/riscv/air/semantics/load_store.zig` through the
symbolic collector export. The export this file was checked against is recorded
as `loadStoreIrDigest`; if the production AIR changes, the digest changes and
this transcription must be re-derived. This file is reviewed hand transcription,
**not** generator output; producing it mechanically from the export is an open
obligation.

Modelling conventions, stated once:

* Every AIR column is a base-field element of `M31 = 2^31 - 1`. A column whose
  production range check pins it to a byte is modelled by `BitVec 8` (grouped
  into `WordBytes`), a column pinned to a five-bit register index by
  `RegisterIndex`, a boolean-constrained column by `Bool`, and every remaining
  scalar column by its **canonical representative** in `[0, M31)` as a `Nat`.
  Modelling a boolean column as `Bool` discharges its `x * (x - 1) = 0`
  constraint by typing; that is noted at each such constraint below.
* `src_addr` and `dst_addr` (columns 2 and 22 of the export) appear in no
  constraint and in no lookup, so they are not modelled here.
* `destination_inverse` (column 55) occurs only in the destination-witness
  constraints C58-C60, whose joint content is the single equation
  `destination_nonzero = [r2_idx ≠ 0]`; it is therefore folded away exactly as
  `RiscvRefinement.Air.Generated.LuiHolds` folds it for `LUI`.
* `src_addr_selector` and `dst_addr_selector` (columns 36 and 37) are *defined*
  by constraints C16 and C17 from the memory address and `r2_idx`, so they are
  derived functions here rather than committed fields.

The constraint numbering `Cnn` used in the comments is the index into the
exported `constraints` array; `Lnn` is the index into the exported `lookups`
array.
-/

namespace RiscvRefinement.Air.Family

open RiscvRefinement

/-- SHA-256 of the exported production symbolic AIR this file transcribes. -/
def loadStoreIrDigest : String :=
  "50339969c53a84fa57fad5a371f2208892c5b08514eafcfd3289f077efc18ce4"

/-- The base field the production AIR evaluates in. -/
def m31Modulus : Nat := 2147483647

/-- Canonical representative of a boolean-constrained AIR column. -/
def bitValue (flag : Bool) : Nat := if flag then 1 else 0

@[simp] theorem bitValue_true : bitValue true = 1 := rfl

@[simp] theorem bitValue_false : bitValue false = 0 := rfl

/-! ## The committed row -/

/-- One `load_store` trace row.

Field order follows the production oracle-column order in
`load_store.zig::Row.fromOracleColumns`. -/
structure LoadStoreRow where
  /-- `clk`. -/
  clock : Nat
  /-- `pc`. -/
  pc : Word
  /-- `dst_previous_*`: the destination access block's consumed limbs. For a
  load this is the `rd` register cell, for a store the target memory word. -/
  dstPrevious : WordBytes
  /-- `dst_previous_clock`. -/
  dstPreviousClock : Nat
  /-- `dst_next_*`. -/
  dstNext : WordBytes
  /-- `rs1_addr`: pinned to a register index by the program relation. -/
  rs1Addr : RegisterIndex
  /-- `rs1_previous_*`. -/
  rs1Previous : WordBytes
  /-- `rs1_previous_clock`. -/
  rs1PreviousClock : Nat
  /-- `rs1_next_*`. -/
  rs1Next : WordBytes
  /-- `src_previous_*`: the source access block's consumed limbs. For a load
  this is the memory word being read, for a store the `rs2` register cell. -/
  srcPrevious : WordBytes
  /-- `src_previous_clock`. -/
  srcPreviousClock : Nat
  /-- `src_next_*`. -/
  srcNext : WordBytes
  /-- `r2_idx`: `rd` for a load and `rs2` for a store; pinned to a register
  index by the program relation. -/
  r2Idx : RegisterIndex
  /-- `imm_felt`: the field encoding of the sign-extended 12-bit displacement,
  supplied by the decoded program ROM. -/
  immFelt : Nat
  /-- `src_msb`: the sign bit of the selected byte or halfword. -/
  srcMsb : Bool
  /-- `shift_amount`: the byte offset of the access inside its aligned word. -/
  shiftAmount : Nat
  /-- The value `L06` range-checks: the aligned word address divided by four. -/
  alignedQuarter : Nat
  /-- `markers_0`. -/
  marker0 : Bool
  /-- `markers_1`. -/
  marker1 : Bool
  /-- `markers_2`. -/
  marker2 : Bool
  /-- `markers_3`. -/
  marker3 : Bool
  /-- `is_lb`. -/
  isLb : Bool
  /-- `is_lh`. -/
  isLh : Bool
  /-- `is_lbu`. -/
  isLbu : Bool
  /-- `is_lhu`. -/
  isLhu : Bool
  /-- `is_lw`. -/
  isLw : Bool
  /-- `is_sb`. -/
  isSb : Bool
  /-- `is_sh`. -/
  isSh : Bool
  /-- `is_sw`. -/
  isSw : Bool
  /-- `result_*`: the architectural load result, pinned to zero on stores. -/
  result : WordBytes
  /-- `destination_nonzero`. -/
  destinationNonzero : Bool
  /-- `bus_value_57`: the emitted next program counter. -/
  claimedNextPc : Word
deriving DecidableEq, Repr

namespace LoadStoreRow

/-- `is_store = is_sb + is_sh + is_sw`. Under C69 at most one flag is set, so
the field sum and the boolean disjunction agree. -/
def isStore (row : LoadStoreRow) : Bool := row.isSb || row.isSh || row.isSw

/-- `is_load = active - is_store`, and C69 pins `active = 1`. -/
def isLoad (row : LoadStoreRow) : Bool := !row.isStore

/-- `opcode_b = is_lbu + is_lb + is_sb`. -/
def isByte (row : LoadStoreRow) : Bool := row.isLb || row.isLbu || row.isSb

/-- `opcode_h = is_lhu + is_lh + is_sh`. -/
def isHalf (row : LoadStoreRow) : Bool := row.isLh || row.isLhu || row.isSh

/-- `opcode_w = is_lw + is_sw`. -/
def isWord (row : LoadStoreRow) : Bool := row.isLw || row.isSw

/-- `load_b = is_lb + is_lbu`. -/
def isByteLoad (row : LoadStoreRow) : Bool := row.isLb || row.isLbu

/-- `load_h = is_lh + is_lhu`. -/
def isHalfLoad (row : LoadStoreRow) : Bool := row.isLh || row.isLhu

/-- `is_signed = is_lb + is_lh`. -/
def isSigned (row : LoadStoreRow) : Bool := row.isLb || row.isLh

/-- `marker_sum`. -/
def markerSum (row : LoadStoreRow) : Nat :=
  bitValue row.marker0 + bitValue row.marker1 +
    bitValue row.marker2 + bitValue row.marker3

/-- `shift_id = Σ i * markers_i`. -/
def shiftId (row : LoadStoreRow) : Nat :=
  bitValue row.marker1 + 2 * bitValue row.marker2 + 3 * bitValue row.marker3

/-- `active`, the sum of the eight opcode flags. -/
def selectorSum (row : LoadStoreRow) : Nat :=
  bitValue row.isLb + bitValue row.isLh + bitValue row.isLbu +
    bitValue row.isLhu + bitValue row.isLw + bitValue row.isSb +
    bitValue row.isSh + bitValue row.isSw

/-- `signed_mask = is_signed * src_msb * 255`, as a byte. -/
def signMask (row : LoadStoreRow) : Byte :=
  if row.isSigned && row.srcMsb then BitVec.ofNat 8 255 else BitVec.ofNat 8 0

/-- The aligned word address the access names on the memory bus. -/
def alignedAddress (row : LoadStoreRow) : Nat := 4 * row.alignedQuarter

/-- The aligned word bus address as a 32-bit architectural address. -/
def busAddress (row : LoadStoreRow) : Word :=
  BitVec.ofNat 32 row.alignedAddress

/-- C16: `src_addr_selector`. -/
def sourceSelector (row : LoadStoreRow) : Nat :=
  if row.isStore then row.r2Idx.toNat else row.alignedAddress

/-- C17: `dst_addr_selector`. -/
def destinationSelector (row : LoadStoreRow) : Nat :=
  if row.isStore then row.alignedAddress else row.r2Idx.toNat

/-- The memory word the access consumes: `src` for a load, `dst` for a store. -/
def memoryBefore (row : LoadStoreRow) : WordBytes :=
  if row.isStore then row.dstPrevious else row.srcPrevious

/-- The memory word the access emits. -/
def memoryAfter (row : LoadStoreRow) : WordBytes :=
  if row.isStore then row.dstNext else row.srcNext

/-- The register cell `r2_idx` names: `dst` for a load, `src` for a store. -/
def operandBefore (row : LoadStoreRow) : WordBytes :=
  if row.isStore then row.srcPrevious else row.dstPrevious

/-- The register cell `r2_idx` emits. -/
def operandAfter (row : LoadStoreRow) : WordBytes :=
  if row.isStore then row.srcNext else row.dstNext

/-- The previous clock of the memory access block. -/
def memoryPreviousClock (row : LoadStoreRow) : Nat :=
  if row.isStore then row.dstPreviousClock else row.srcPreviousClock

/-- The previous clock of the `r2_idx` register access block. -/
def operandPreviousClock (row : LoadStoreRow) : Nat :=
  if row.isStore then row.srcPreviousClock else row.dstPreviousClock

/-- Byte offset inside the aligned word, as the architectural two-bit offset. -/
def byteOffset (row : LoadStoreRow) : BitVec 2 :=
  BitVec.ofNat 2 row.shiftAmount

/-- Halfword selector inside the aligned word. -/
def halfSelector (row : LoadStoreRow) : BitVec 1 :=
  BitVec.ofNat 1 (row.shiftAmount / 2)

/-- Byte-enable mask of a store. Loads leave this unused. -/
def mask (row : LoadStoreRow) : ByteMask :=
  if row.isSb then Memory.byteMask row.byteOffset
  else if row.isSh then Memory.halfMask row.halfSelector
  else Memory.wordMask

/-- Program relation opcode identifier: `LB=19`, `LH=20`, `LW=21`, `LBU=22`,
`LHU=23`, `SB=24`, `SH=25`, `SW=26`. -/
def opcodeId (row : LoadStoreRow) : Nat :=
  19 * bitValue row.isLb + 20 * bitValue row.isLh + 21 * bitValue row.isLw +
    22 * bitValue row.isLbu + 23 * bitValue row.isLhu +
    24 * bitValue row.isSb + 25 * bitValue row.isSh + 26 * bitValue row.isSw

end LoadStoreRow

/-! ## The constraint system -/

/-- The production constraints this development relies on, transcribed from the
exported symbolic AIR.

Every field cites the exported constraint index it comes from. Constraints
C01-C09 and C11-C14 (the `x * (x - 1) = 0` residuals on the eight opcode flags,
on `src_msb`, and on the four markers) are discharged by the `Bool` typing of
the corresponding row fields and therefore have no field here. -/
structure LoadStoreHolds (row : LoadStoreRow) : Prop where
  /-- The instruction clock of a placed row. -/
  clockPositive : 0 < row.clock
  /-- C00 and C69: `active * (active - 1) = 0` together with the placement
  residual `active - 1 = 0`, so exactly one opcode flag is set. -/
  selectorSum : row.selectorSum = 1
  /-- C10: `(1 - is_signed) * src_msb = 0`. -/
  signWitnessCanonical : row.isSigned = false → row.srcMsb = false
  /-- C18: `opcode_b * (1 - marker_sum) = 0`. -/
  byteMarkerSum : row.isByte = true → row.markerSum = 1
  /-- C19: `opcode_h * (2 - marker_sum) = 0`. -/
  halfMarkerSum : row.isHalf = true → row.markerSum = 2
  /-- C20: `opcode_h * (1 - shift_id) * (5 - shift_id) = 0`. -/
  halfShiftId : row.isHalf = true → row.shiftId = 1 ∨ row.shiftId = 5
  /-- C15, byte branch: `shift_amount = opcode_b * shift_id`. -/
  byteShiftAmount : row.isByte = true → row.shiftAmount = row.shiftId
  /-- C15, halfword branch: `shift_amount = opcode_h * (shift_id - 1) / 2`.
  C20 pins `shift_id ∈ {1, 5}`, so over the canonical representatives this is
  exactly `2 * shift_amount + 1 = shift_id`. -/
  halfShiftAmount : row.isHalf = true → 2 * row.shiftAmount + 1 = row.shiftId
  /-- C15, word branch: neither `opcode_b` nor `opcode_h` fires. -/
  wordShiftAmount : row.isWord = true → row.shiftAmount = 0
  /-- L06: the aligned word address divided by four is a 20-bit value, so the
  modelled address space is the aligned 4 MiB region `[0, 2^22)`. -/
  alignedQuarterRange : row.alignedQuarter < 2 ^ 20
  /-- C16 and C17 jointly: whichever of the two address selectors carries the
  memory address equals `compose(rs1_next) + imm_felt - shift_amount` in the
  base field, and L06 pins that selector to `4 * aligned_quarter`. The right
  hand side is below `2^22 + 4`, hence already canonical. -/
  memoryAddress :
    (row.rs1Next.value + row.immFelt) % m31Modulus =
      row.alignedAddress + row.shiftAmount
  /-- `imm_felt` is a base-field element. -/
  immFeltRange : row.immFelt < m31Modulus
  /-- L07, first component: `rs1_next_0` is a byte (typing) and, second
  component, `rs1_next_3` is a seven-bit value. -/
  baseHighLimbRange : row.rs1Next.limb3.toNat < 128
  /-- L07: the `range_check_m31` table omits the tuple `(255, 127)`, which is
  exactly what keeps `compose(rs1_next)` below the modulus. -/
  baseLimbsCanonical :
    row.rs1Next.limb0.toNat ≠ 255 ∨ row.rs1Next.limb3.toNat ≠ 127
  /-- C21-C23: `load_b * (signed_mask - result_i) = 0` for `i ∈ {1,2,3}`. -/
  byteLoadExtension :
    row.isByteLoad = true →
      row.result.limb1 = row.signMask ∧
        row.result.limb2 = row.signMask ∧
        row.result.limb3 = row.signMask
  /-- C24, C26, C28, C30: `load_b * (result_0 - src_next_i) * markers_i = 0`. -/
  byteLoadSelect :
    row.isByteLoad = true →
      (row.marker0 = true → row.result.limb0 = row.srcNext.limb0) ∧
        (row.marker1 = true → row.result.limb0 = row.srcNext.limb1) ∧
        (row.marker2 = true → row.result.limb0 = row.srcNext.limb2) ∧
        (row.marker3 = true → row.result.limb0 = row.srcNext.limb3)
  /-- C25, C27, C29, C31: `is_sb * (dst_next_i - src_next_0) * markers_i = 0`. -/
  byteStoreSelect :
    row.isSb = true →
      (row.marker0 = true → row.dstNext.limb0 = row.srcNext.limb0) ∧
        (row.marker1 = true → row.dstNext.limb1 = row.srcNext.limb0) ∧
        (row.marker2 = true → row.dstNext.limb2 = row.srcNext.limb0) ∧
        (row.marker3 = true → row.dstNext.limb3 = row.srcNext.limb0)
  /-- C32-C33: `load_h * (signed_mask - result_i) = 0` for `i ∈ {2,3}`. -/
  halfLoadExtension :
    row.isHalfLoad = true →
      row.result.limb2 = row.signMask ∧ row.result.limb3 = row.signMask
  /-- C34-C35: `load_h * ((5 - shift_id) / 4) * (result_i - src_next_i) = 0`.
  The gate is `1` exactly when `shift_id = 1`. -/
  halfLoadLow :
    row.isHalfLoad = true → row.shiftId = 1 →
      row.result.limb0 = row.srcNext.limb0 ∧
        row.result.limb1 = row.srcNext.limb1
  /-- C36-C37: `load_h * ((shift_id - 1) / 4) * (result_i - src_next_{i+2}) = 0`.
  The gate is `1` exactly when `shift_id = 5`. -/
  halfLoadHigh :
    row.isHalfLoad = true → row.shiftId = 5 →
      row.result.limb0 = row.srcNext.limb2 ∧
        row.result.limb1 = row.srcNext.limb3
  /-- C38-C39. -/
  halfStoreLow :
    row.isSh = true → row.shiftId = 1 →
      row.dstNext.limb0 = row.srcNext.limb0 ∧
        row.dstNext.limb1 = row.srcNext.limb1
  /-- C40-C41. -/
  halfStoreHigh :
    row.isSh = true → row.shiftId = 5 →
      row.dstNext.limb2 = row.srcNext.limb0 ∧
        row.dstNext.limb3 = row.srcNext.limb1
  /-- C42-C45, load half: `is_lw * (result_i - src_next_i) = 0`. -/
  wordLoad : row.isLw = true → row.result = row.srcNext
  /-- C42-C45, store half: `is_sw * (dst_next_i - src_next_i) = 0`. -/
  wordStore : row.isSw = true → row.dstNext = row.srcNext
  /-- C46-C49: the base register access is read-only. -/
  baseReadOnly : row.rs1Next = row.rs1Previous
  /-- C50-C53: the source access is read-only in both directions. For a load
  this is the memory-preservation constraint; for a store it is `rs2`. -/
  sourceReadOnly : row.srcNext = row.srcPrevious
  /-- C54-C57: `(is_sb + is_sh) * (1 - markers_i) * (dst_next_i - dst_previous_i)`
  — an unmarked byte of a partial store survives unchanged. -/
  partialStorePreserve :
    row.isSb = true ∨ row.isSh = true →
      (row.marker0 = false → row.dstNext.limb0 = row.dstPrevious.limb0) ∧
        (row.marker1 = false → row.dstNext.limb1 = row.dstPrevious.limb1) ∧
        (row.marker2 = false → row.dstNext.limb2 = row.dstPrevious.limb2) ∧
        (row.marker3 = false → row.dstNext.limb3 = row.dstPrevious.limb3)
  /-- C58-C60: `nonzero * (nonzero - 1) = 0`, `r2_idx * (1 - nonzero) = 0` and
  `r2_idx * inverse - nonzero = 0` jointly say exactly this. -/
  destinationFlag :
    row.destinationNonzero = decide (row.r2Idx ≠ zeroRegister)
  /-- C61-C64: `is_load * (dst_next_i - nonzero * result_i) = 0`. -/
  loadDestination :
    row.isLoad = true →
      row.dstNext = if row.destinationNonzero then row.result else WordBytes.zero
  /-- C65-C68: `(1 - is_load) * result_i = 0`. -/
  storeResultZero : row.isStore = true → row.result = WordBytes.zero
  /-- L14: `range_check_m31` on `(0, result_0 - 128 * src_msb)` forces the
  residual into seven bits, so `src_msb` is bit 7 of the selected byte. -/
  byteSignWitness : row.isLb = true → row.srcMsb = row.result.limb0.getLsbD 7
  /-- L15: `range_check_m31` on `(0, result_1 - 128 * src_msb)` forces the
  residual into seven bits, so `src_msb` is bit 15 of the selected halfword. -/
  halfSignWitness : row.isLh = true → row.srcMsb = row.result.limb1.getLsbD 7
  /-- L05: the base register access advances the register clock. -/
  baseClock : validPreviousClock row.rs1PreviousClock (accessClock row.clock 1)
  /-- L10 for a store and L13 for a load: the `r2_idx` register access sits at
  ordinal two. -/
  operandClock :
    validPreviousClock row.operandPreviousClock (accessClock row.clock 2)
  /-- L13 for a store and L10 for a load: the memory access sits at ordinal
  three. -/
  memoryClock :
    validPreviousClock row.memoryPreviousClock (accessClock row.clock 3)
  /-- C71: `bus_value_57 = pc + 4`. -/
  nextPcResult : row.claimedNextPc = nextPc row.pc

/-! ## Normalized retirement and relation tuples -/

/-- The complete normalized architectural retirement the row claims. A load
records a memory read and at most one register write; a store records a masked
memory write and no register write. -/
def loadStoreRetirement (row : LoadStoreRow) : Retirement where
  nextPc := row.claimedNextPc
  write :=
    if row.isStore then none
    else architecturalWrite row.r2Idx row.dstNext.word
  read :=
    if row.isStore then none
    else some { address := row.busAddress, value := row.srcNext.word }
  store :=
    if row.isStore then
      some {
        address := row.busAddress
        mask := row.mask
        value := row.dstNext.word
      }
    else none

/-- L00. The production program relation places `rs1_addr` in the tuple's `rd`
slot and `r2_idx` in its `rs1` slot; that slot order is transcribed as-is so
the decoded ROM this family binds against is pinned to the same convention. -/
def loadStoreProgramTuple (row : LoadStoreRow) : ProgramTuple where
  pc := row.pc
  opcodeId := row.opcodeId
  rd := row.rs1Addr.toNat
  rs1 := row.r2Idx.toNat
  operand := row.immFelt

/-- The complete relation footprint of one `load_store` row. -/
structure LoadStoreRelations where
  program : ProgramTuple
  stateConsume : StateTuple
  stateEmit : StateTuple
  baseConsume : RegisterTuple
  baseEmit : RegisterTuple
  operandConsume : RegisterTuple
  operandEmit : RegisterTuple
  memoryConsume : MemoryTuple
  memoryEmit : MemoryTuple
deriving DecidableEq, Repr

/-- L00-L04, L08-L09 and L11-L12 at their exact access-clock ordinals: the base
register at ordinal one, the `r2_idx` register at ordinal two, and the memory
word at ordinal three.

The production `memory_access` relation carries an address-space component,
`0` for the register file and `1` for memory (`L08`/`L09` use `is_load` and
`L11`/`L12` use `is_store`, which is why a load's `src` block is memory and a
store's `src` block is a register). Here that component is carried by the type:
register accesses are `RegisterTuple`s and memory accesses are `MemoryTuple`s,
and `operandBefore`/`memoryBefore` route the two committed access blocks to the
right side for each direction. -/
def loadStoreRelations (row : LoadStoreRow) : LoadStoreRelations where
  program := loadStoreProgramTuple row
  stateConsume := { pc := row.pc, clock := row.clock }
  stateEmit := { pc := nextPc row.pc, clock := row.clock + 1 }
  baseConsume := {
    addr := row.rs1Addr
    clock := row.rs1PreviousClock
    value := row.rs1Previous.word
  }
  baseEmit := {
    addr := row.rs1Addr
    clock := accessClock row.clock 1
    value := row.rs1Next.word
  }
  operandConsume := {
    addr := row.r2Idx
    clock := row.operandPreviousClock
    value := row.operandBefore.word
  }
  operandEmit := {
    addr := row.r2Idx
    clock := accessClock row.clock 2
    value := row.operandAfter.word
  }
  memoryConsume := {
    addr := row.busAddress
    clock := row.memoryPreviousClock
    value := row.memoryBefore.word
  }
  memoryEmit := {
    addr := row.busAddress
    clock := accessClock row.clock 3
    value := row.memoryAfter.word
  }

end RiscvRefinement.Air.Family
