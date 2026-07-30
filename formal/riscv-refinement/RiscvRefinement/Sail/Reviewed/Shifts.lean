import RiscvRefinement.Common

/-!
# Reviewed architectural capsule: RV32I shift instructions

**Boundary.** This file is a *reviewed normalized capsule* of the architectural
meaning of `SLLI`, `SRLI`, `SRAI`, `SLL`, `SRL` and `SRA`. It is **not** a
generated pinned-Sail theorem: no Sail compiler was available in the environment
that produced it, so unlike a generated backend it carries no Sail definition
digests and no extraction receipt. Replacing this capsule with the generated
pinned-Sail definitions -- and re-checking every `*_refines` theorem against
them unchanged -- is the open obligation for this family. Nothing here may be
read as publication-level or generated-Sail status.

The capsule follows the same normalization as
`RiscvRefinement/Sail/Generated/Pilot.lean`: each instruction denotes a
`Retirement`, i.e. a next program counter, at most one architectural register
write, and -- for these six instructions -- no memory effect at all, which is
why `read` and `store` keep their `none` defaults.

## Content being asserted

* `SLLI`/`SRLI`/`SRAI` shift `X(rs1)` by the five-bit `shamt` field of the
  instruction word. RV32I has no six-bit shift form, so the shift amount is the
  field itself, with no masking step.
* `SLL`/`SRL`/`SRA` shift `X(rs1)` by `X(rs2)[4..0]`, i.e. by the register value
  masked to five bits. `registerShiftAmount` is that mask.
* The right shifts differ only in fill: `SRL`/`SRLI` zero-fill
  (`BitVec.ushiftRight`), `SRA`/`SRAI` replicate bit 31
  (`BitVec.sshiftRight`).
* All six advance the program counter by four and touch no memory.
-/

namespace RiscvRefinement.Sail.Reviewed

open RiscvRefinement

/-- `X(rs2)[4..0]`: the RV32 five-bit mask applied to a register-sourced shift
amount. -/
def registerShiftAmount (value : Word) : BitVec 5 :=
  BitVec.setWidth 5 value

@[simp]
theorem registerShiftAmount_toNat (value : Word) :
    (registerShiftAmount value).toNat = value.toNat % 32 := by
  simp [registerShiftAmount]

/-- Logical left shift. -/
def executeSllValue (source : Word) (amount : BitVec 5) : Word :=
  source <<< amount.toNat

/-- Logical right shift: zero fill. -/
def executeSrlValue (source : Word) (amount : BitVec 5) : Word :=
  source >>> amount.toNat

/-- Arithmetic right shift: fill with bit 31 of the operand. -/
def executeSraValue (source : Word) (amount : BitVec 5) : Word :=
  source.sshiftRight amount.toNat

/-- A shift by zero is the identity, for all three fills. -/
theorem shift_by_zero (source : Word) :
    executeSllValue source (BitVec.ofNat 5 0) = source ∧
      executeSrlValue source (BitVec.ofNat 5 0) = source ∧
      executeSraValue source (BitVec.ofNat 5 0) = source := by
  simp only [executeSllValue, executeSrlValue, executeSraValue,
    BitVec.toNat_ofNat]
  refine ⟨?_, ?_, ?_⟩ <;> bv_decide

/-- The two right shifts genuinely differ on a negative operand: this is the
statement the `SRAI`/`SRA` sign-fill gate has to earn. -/
theorem arithmetic_and_logical_right_shifts_differ :
    executeSraValue (BitVec.ofNat 32 0x80000000) (BitVec.ofNat 5 1) =
        BitVec.ofNat 32 0xc0000000 ∧
      executeSrlValue (BitVec.ofNat 32 0x80000000) (BitVec.ofNat 5 1) =
        BitVec.ofNat 32 0x40000000 := by
  refine ⟨?_, ?_⟩ <;> decide

def executeSlli
    (pc source : Word)
    (rd : RegisterIndex)
    (shamt : BitVec 5) :
    Retirement where
  nextPc := nextPc pc
  write := architecturalWrite rd (executeSllValue source shamt)

def executeSrli
    (pc source : Word)
    (rd : RegisterIndex)
    (shamt : BitVec 5) :
    Retirement where
  nextPc := nextPc pc
  write := architecturalWrite rd (executeSrlValue source shamt)

def executeSrai
    (pc source : Word)
    (rd : RegisterIndex)
    (shamt : BitVec 5) :
    Retirement where
  nextPc := nextPc pc
  write := architecturalWrite rd (executeSraValue source shamt)

def executeSll
    (pc source amount : Word)
    (rd : RegisterIndex) :
    Retirement where
  nextPc := nextPc pc
  write :=
    architecturalWrite rd (executeSllValue source (registerShiftAmount amount))

def executeSrl
    (pc source amount : Word)
    (rd : RegisterIndex) :
    Retirement where
  nextPc := nextPc pc
  write :=
    architecturalWrite rd (executeSrlValue source (registerShiftAmount amount))

def executeSra
    (pc source amount : Word)
    (rd : RegisterIndex) :
    Retirement where
  nextPc := nextPc pc
  write :=
    architecturalWrite rd (executeSraValue source (registerShiftAmount amount))

/-- None of the six shifts has a memory effect. -/
theorem shifts_have_no_memory_effect
    (pc source amount : Word)
    (rd : RegisterIndex)
    (shamt : BitVec 5) :
    (executeSlli pc source rd shamt).read = none ∧
      (executeSlli pc source rd shamt).store = none ∧
      (executeSrli pc source rd shamt).read = none ∧
      (executeSrli pc source rd shamt).store = none ∧
      (executeSrai pc source rd shamt).read = none ∧
      (executeSrai pc source rd shamt).store = none ∧
      (executeSll pc source amount rd).read = none ∧
      (executeSll pc source amount rd).store = none ∧
      (executeSrl pc source amount rd).read = none ∧
      (executeSrl pc source amount rd).store = none ∧
      (executeSra pc source amount rd).read = none ∧
      (executeSra pc source amount rd).store = none :=
  ⟨rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl⟩

/-- Every shift advances the program counter by four. -/
theorem shifts_advance_pc
    (pc source amount : Word)
    (rd : RegisterIndex)
    (shamt : BitVec 5) :
    (executeSlli pc source rd shamt).nextPc = nextPc pc ∧
      (executeSrli pc source rd shamt).nextPc = nextPc pc ∧
      (executeSrai pc source rd shamt).nextPc = nextPc pc ∧
      (executeSll pc source amount rd).nextPc = nextPc pc ∧
      (executeSrl pc source amount rd).nextPc = nextPc pc ∧
      (executeSra pc source amount rd).nextPc = nextPc pc :=
  ⟨rfl, rfl, rfl, rfl, rfl, rfl⟩

/-- Writing to `x0` is architecturally silent for every shift. -/
theorem shifts_to_x0_are_silent
    (pc source amount : Word)
    (shamt : BitVec 5) :
    (executeSlli pc source zeroRegister shamt).write = none ∧
      (executeSrli pc source zeroRegister shamt).write = none ∧
      (executeSrai pc source zeroRegister shamt).write = none ∧
      (executeSll pc source amount zeroRegister).write = none ∧
      (executeSrl pc source amount zeroRegister).write = none ∧
      (executeSra pc source amount zeroRegister).write = none := by
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_⟩ <;>
    simp [executeSlli, executeSrli, executeSrai, executeSll, executeSrl,
      executeSra, architecturalWrite]

end RiscvRefinement.Sail.Reviewed
