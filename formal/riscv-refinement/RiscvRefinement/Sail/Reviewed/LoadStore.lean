-- REVIEWED NORMALIZED CAPSULE. NOT A GENERATED-SAIL THEOREM.
--
-- This file states the architectural half of the RV32I load/store contract as a
-- hand-written, human-reviewed normalized capsule. It is the same epistemic
-- *class* as RiscvRefinement/Sail/Generated/Pilot.lean -- a reviewed capsule,
-- not a generated-Sail theorem -- but not the same status: Pilot.lean is
-- generator output pinned to SHA-256 digests of real generated Sail text,
-- while this file is hand-written, with no generator, no digest, and no
-- derivation from any Sail artifact. The generated pinned-Sail theorem
-- backend is not available in this environment (no Sail compiler), so nothing
-- here is machine-derived from the Sail model.
--
-- OPEN OBLIGATION: replace every definition below with the corresponding slice
-- of the generated exact-profile Sail theorem backend for `execute(LOAD(..))`
-- and `execute(STORE(..))`, and re-run the opcode refinement proofs against it.
-- Until that is done, no claim in this development is publication-level for the
-- load/store family: the architectural side is reviewed, not generated.

import RiscvRefinement.Memory

/-!
# Reviewed architectural capsule: RV32I loads and stores

The eight covered instructions are `LB`, `LH`, `LW`, `LBU`, `LHU`, `SB`, `SH`
and `SW`. All of them share one shape:

* the effective address is `rs1 + signExtend(imm12)` under 32-bit modular
  arithmetic — address wrap is architectural, not an error;
* narrow accesses carry a natural-alignment premise (`LH`/`LHU`/`SH` need bit
  zero clear, `LW`/`SW` need bits one and zero clear);
* memory is a little-endian array of aligned 32-bit words, so every access
  names the aligned word bus address and selects inside that word;
* a load sign- or zero-extends the selected byte or halfword into `rd`, and
  writing `x0` is discarded;
* a store commits the aligned word under a byte-enable mask and performs no
  register write.
-/

namespace RiscvRefinement.Sail.Reviewed

open RiscvRefinement

/-! ## Natural alignment premises -/

/-- `LH`, `LHU` and `SH` require a halfword-aligned effective address. -/
def halfAccessAligned (base : Word) (imm : BitVec 12) : Prop :=
  Memory.isHalfAligned (Memory.effectiveAddress base imm)

/-- `LW` and `SW` require a word-aligned effective address. -/
def wordAccessAligned (base : Word) (imm : BitVec 12) : Prop :=
  Memory.isWordAligned (Memory.effectiveAddress base imm)

/-! ## Load result values -/

/-- `LB`: sign-extended little-endian byte at the effective address. -/
def loadByteSignedValue
    (base : Word) (imm : BitVec 12) (memory : WordBytes) : Word :=
  Memory.signExtendByte
    (Memory.selectByte memory
      (Memory.byteOffset (Memory.effectiveAddress base imm)))

/-- `LBU`: zero-extended little-endian byte at the effective address. -/
def loadByteUnsignedValue
    (base : Word) (imm : BitVec 12) (memory : WordBytes) : Word :=
  Memory.zeroExtendByte
    (Memory.selectByte memory
      (Memory.byteOffset (Memory.effectiveAddress base imm)))

/-- `LH`: sign-extended little-endian halfword at the effective address. -/
def loadHalfSignedValue
    (base : Word) (imm : BitVec 12) (memory : WordBytes) : Word :=
  Memory.signExtendHalf
    (Memory.selectHalf memory
      (Memory.halfSelector (Memory.effectiveAddress base imm)))

/-- `LHU`: zero-extended little-endian halfword at the effective address. -/
def loadHalfUnsignedValue
    (base : Word) (imm : BitVec 12) (memory : WordBytes) : Word :=
  Memory.zeroExtendHalf
    (Memory.selectHalf memory
      (Memory.halfSelector (Memory.effectiveAddress base imm)))

/-- `LW`: the aligned word itself. -/
def loadWordValue (memory : WordBytes) : Word := memory.word

/-! ## Store payload placement

A store's payload is placed at every position its mask could select; the
byte-enable mask then keeps exactly the architectural bytes. Writing the
payload this way makes the placement definitions independent of the selector,
which is what lets one masked-commit definition serve all three widths. -/

/-- `SB` payload: the low byte of `rs2` in every limb. -/
def storeBytePayload (source : Word) : WordBytes where
  limb0 := BitVec.extractLsb 7 0 source
  limb1 := BitVec.extractLsb 7 0 source
  limb2 := BitVec.extractLsb 7 0 source
  limb3 := BitVec.extractLsb 7 0 source

/-- `SH` payload: the low halfword of `rs2` in both halves, little-endian. -/
def storeHalfPayload (source : Word) : WordBytes where
  limb0 := BitVec.extractLsb 7 0 source
  limb1 := BitVec.extractLsb 15 8 source
  limb2 := BitVec.extractLsb 7 0 source
  limb3 := BitVec.extractLsb 15 8 source

/-- `SW` payload: the whole of `rs2`, little-endian. -/
def storeWordPayload (source : Word) : WordBytes where
  limb0 := BitVec.extractLsb 7 0 source
  limb1 := BitVec.extractLsb 15 8 source
  limb2 := BitVec.extractLsb 23 16 source
  limb3 := BitVec.extractLsb 31 24 source

/-! ## Normalized retirements -/

/-- Shared load retirement: `pc + 4`, one guarded register write, and the
memory observation naming the aligned word bus address and the complete word
observed there. Loads never populate `store`. -/
def executeLoad
    (pc base : Word)
    (imm : BitVec 12)
    (rd : RegisterIndex)
    (memory : WordBytes)
    (value : Word) :
    Retirement where
  nextPc := nextPc pc
  write := architecturalWrite rd value
  read := some {
    address := Memory.busAddress (Memory.effectiveAddress base imm)
    value := memory.word
  }
  store := none

/-- Shared store retirement: `pc + 4`, no register write, no read observation,
and the masked aligned word commit. Bytes outside `mask` keep their pre-state
value by construction of `Memory.applyMask`. -/
def executeStore
    (pc base : Word)
    (imm : BitVec 12)
    (memory payload : WordBytes)
    (mask : ByteMask) :
    Retirement where
  nextPc := nextPc pc
  write := none
  read := none
  store := some {
    address := Memory.busAddress (Memory.effectiveAddress base imm)
    mask := mask
    value := (Memory.applyMask memory payload mask).word
  }

def executeLb
    (pc base : Word) (imm : BitVec 12) (rd : RegisterIndex)
    (memory : WordBytes) : Retirement :=
  executeLoad pc base imm rd memory (loadByteSignedValue base imm memory)

def executeLbu
    (pc base : Word) (imm : BitVec 12) (rd : RegisterIndex)
    (memory : WordBytes) : Retirement :=
  executeLoad pc base imm rd memory (loadByteUnsignedValue base imm memory)

def executeLh
    (pc base : Word) (imm : BitVec 12) (rd : RegisterIndex)
    (memory : WordBytes) : Retirement :=
  executeLoad pc base imm rd memory (loadHalfSignedValue base imm memory)

def executeLhu
    (pc base : Word) (imm : BitVec 12) (rd : RegisterIndex)
    (memory : WordBytes) : Retirement :=
  executeLoad pc base imm rd memory (loadHalfUnsignedValue base imm memory)

def executeLw
    (pc base : Word) (imm : BitVec 12) (rd : RegisterIndex)
    (memory : WordBytes) : Retirement :=
  executeLoad pc base imm rd memory (loadWordValue memory)

def executeSb
    (pc base : Word) (imm : BitVec 12) (source : Word)
    (memory : WordBytes) : Retirement :=
  executeStore pc base imm memory (storeBytePayload source)
    (Memory.byteMask (Memory.byteOffset (Memory.effectiveAddress base imm)))

def executeSh
    (pc base : Word) (imm : BitVec 12) (source : Word)
    (memory : WordBytes) : Retirement :=
  executeStore pc base imm memory (storeHalfPayload source)
    (Memory.halfMask (Memory.halfSelector (Memory.effectiveAddress base imm)))

def executeSw
    (pc base : Word) (imm : BitVec 12) (source : Word)
    (memory : WordBytes) : Retirement :=
  executeStore pc base imm memory (storeWordPayload source) Memory.wordMask

/-! ## Capsule-level sanity facts

These are not the refinement theorems; they are the review anchors that fix the
capsule's intended reading. -/

/-- A store never claims a register write. -/
theorem executeStore_no_write
    (pc base : Word) (imm : BitVec 12) (memory payload : WordBytes)
    (mask : ByteMask) :
    (executeStore pc base imm memory payload mask).write = none := rfl

/-- A load never claims a memory write. -/
theorem executeLoad_no_store
    (pc base : Word) (imm : BitVec 12) (rd : RegisterIndex)
    (memory : WordBytes) (value : Word) :
    (executeLoad pc base imm rd memory value).store = none := rfl

/-- `SW` overwrites the entire aligned word with `rs2`. -/
theorem executeSw_full_overwrite
    (pc base : Word) (imm : BitVec 12) (source : Word) (memory : WordBytes) :
    (executeSw pc base imm source memory).store =
      some {
        address := Memory.busAddress (Memory.effectiveAddress base imm)
        mask := Memory.wordMask
        value := (storeWordPayload source).word
      } := by
  simp [executeSw, executeStore, Memory.applyMask_word]

/-- `SW`'s payload is exactly `rs2`. -/
theorem storeWordPayload_word (source : Word) :
    (storeWordPayload source).word = source := by
  rw [WordBytes.word_append]
  simp only [storeWordPayload]
  bv_decide

end RiscvRefinement.Sail.Reviewed
