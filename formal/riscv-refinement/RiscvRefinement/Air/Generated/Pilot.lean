-- GENERATED FILE. DO NOT EDIT.
-- Generator: scripts/riscv_refinement.py
-- Regenerate: python3 scripts/riscv_refinement.py generate
-- Production binding: symbolic collector plus exact structural validation.
-- Boundary: normalized predicate; no Lean serialized-M31 interpreter yet.

import RiscvRefinement.Common

namespace RiscvRefinement.Air.Generated

open RiscvRefinement

def luiAirDigest : String := "d9160151ffa202a8166fc6ac01667c55afeeffd3270d0f3f299cfdd2af083c6e"

def addiAirDigest : String := "1194f253ccb702c7f4f35995c815b32e00c460a9af0d2c9056bdc0b16b8dd61a"

def luiImmediate
    (imm0 : BitVec 4)
    (imm1 imm2 : BitVec 8) :
    BitVec 20 :=
  imm2.append (imm1.append imm0)

def luiResult
    (imm0 : BitVec 4)
    (imm1 imm2 : BitVec 8) :
    Word :=
  (luiImmediate imm0 imm1 imm2).append (BitVec.ofNat 12 0)

def luiResultBytes
    (imm0 : BitVec 4)
    (imm1 imm2 : BitVec 8) :
    WordBytes where
  limb0 := BitVec.ofNat 8 0
  limb1 := imm0.append (BitVec.ofNat 4 0)
  limb2 := imm1
  limb3 := imm2

structure LuiRow where
  pc : Word
  clock : Nat
  rd : RegisterIndex
  rdPreviousClock : Nat
  rdPrevious : WordBytes
  rdNext : WordBytes
  imm0 : BitVec 4
  imm1 : BitVec 8
  imm2 : BitVec 8
  rdNonzero : Bool
  claimedNextPc : Word
deriving DecidableEq, Repr

structure LuiHolds (row : LuiRow) : Prop where
  clockPositive : 0 < row.clock
  destinationClock :
    validPreviousClock
      row.rdPreviousClock
      (accessClock row.clock 1)
  destinationFlag :
    row.rdNonzero = decide (row.rd ≠ zeroRegister)
  destinationLimb0 :
    row.rdNext.limb0 =
      if row.rdNonzero
      then (luiResultBytes row.imm0 row.imm1 row.imm2).limb0
      else WordBytes.zero.limb0
  destinationLimb1 :
    row.rdNext.limb1 =
      if row.rdNonzero
      then (luiResultBytes row.imm0 row.imm1 row.imm2).limb1
      else WordBytes.zero.limb1
  destinationLimb2 :
    row.rdNext.limb2 =
      if row.rdNonzero
      then (luiResultBytes row.imm0 row.imm1 row.imm2).limb2
      else WordBytes.zero.limb2
  destinationLimb3 :
    row.rdNext.limb3 =
      if row.rdNonzero
      then (luiResultBytes row.imm0 row.imm1 row.imm2).limb3
      else WordBytes.zero.limb3
  nextPcResult : row.claimedNextPc = nextPc row.pc

def luiRetirement (row : LuiRow) : Retirement where
  nextPc := row.claimedNextPc
  write := architecturalWrite row.rd row.rdNext.word

def luiProgramTuple (row : LuiRow) : ProgramTuple where
  pc := row.pc
  opcodeId := 35
  rd := row.rd.toNat
  rs1 := (luiImmediate row.imm0 row.imm1 row.imm2).toNat
  operand := 0

structure LuiRelations where
  program : ProgramTuple
  stateConsume : StateTuple
  stateEmit : StateTuple
  destinationConsume : RegisterTuple
  destinationEmit : RegisterTuple
deriving DecidableEq, Repr

def luiRelations (row : LuiRow) : LuiRelations where
  program := luiProgramTuple row
  stateConsume := { pc := row.pc, clock := row.clock }
  stateEmit := { pc := nextPc row.pc, clock := row.clock + 1 }
  destinationConsume := {
    addr := row.rd
    clock := row.rdPreviousClock
    value := row.rdPrevious.word
  }
  destinationEmit := {
    addr := row.rd
    clock := accessClock row.clock 1
    value := row.rdNext.word
  }

def addiImmediate
    (imm0 : BitVec 8)
    (imm1 : BitVec 3)
    (sign : BitVec 1) :
    BitVec 12 :=
  sign.append (imm1.append imm0)

def addiImmediateValue
    (imm0 : BitVec 8)
    (imm1 : BitVec 3)
    (sign : BitVec 1) :
    Nat :=
  imm0.toNat +
    256 * (imm1.toNat + 248 * sign.toNat) +
    65536 * (255 * sign.toNat) +
    16777216 * (255 * sign.toNat)

def addiAirImmediate
    (imm0 : BitVec 8)
    (imm1 : BitVec 3)
    (sign : BitVec 1) :
    Word :=
  BitVec.ofNat 32 (addiImmediateValue imm0 imm1 sign)

def addiResult
    (source : Word)
    (imm0 : BitVec 8)
    (imm1 : BitVec 3)
    (sign : BitVec 1) :
    Word :=
  source + addiAirImmediate imm0 imm1 sign

structure AddiRow where
  pc : Word
  clock : Nat
  rd : RegisterIndex
  rdPreviousClock : Nat
  rdPrevious : WordBytes
  rdNext : WordBytes
  rs1 : RegisterIndex
  rs1PreviousClock : Nat
  rs1Previous : WordBytes
  rs1Next : WordBytes
  imm0 : BitVec 8
  imm1 : BitVec 3
  immSign : BitVec 1
  result : WordBytes
  rdNonzero : Bool
  claimedNextPc : Word
deriving DecidableEq, Repr

structure AddiHolds (row : AddiRow) : Prop where
  clockPositive : 0 < row.clock
  sourceClock :
    validPreviousClock
      row.rs1PreviousClock
      (accessClock row.clock 1)
  destinationClock :
    validPreviousClock
      row.rdPreviousClock
      (accessClock row.clock 2)
  sourceLimb0 : row.rs1Next.limb0 = row.rs1Previous.limb0
  sourceLimb1 : row.rs1Next.limb1 = row.rs1Previous.limb1
  sourceLimb2 : row.rs1Next.limb2 = row.rs1Previous.limb2
  sourceLimb3 : row.rs1Next.limb3 = row.rs1Previous.limb3
  carryRecurrence :
    ∃ carry1 carry2 carry3 carry4 : BitVec 1,
      row.rs1Next.limb0.toNat + row.imm0.toNat =
          row.result.limb0.toNat + 256 * carry1.toNat ∧
      row.rs1Next.limb1.toNat +
            (row.imm1.toNat + 248 * row.immSign.toNat) +
            carry1.toNat =
          row.result.limb1.toNat + 256 * carry2.toNat ∧
      row.rs1Next.limb2.toNat +
            255 * row.immSign.toNat +
            carry2.toNat =
          row.result.limb2.toNat + 256 * carry3.toNat ∧
      row.rs1Next.limb3.toNat +
            255 * row.immSign.toNat +
            carry3.toNat =
          row.result.limb3.toNat + 256 * carry4.toNat
  destinationFlag :
    row.rdNonzero = decide (row.rd ≠ zeroRegister)
  destinationLimb0 :
    row.rdNext.limb0 =
      if row.rdNonzero then row.result.limb0 else WordBytes.zero.limb0
  destinationLimb1 :
    row.rdNext.limb1 =
      if row.rdNonzero then row.result.limb1 else WordBytes.zero.limb1
  destinationLimb2 :
    row.rdNext.limb2 =
      if row.rdNonzero then row.result.limb2 else WordBytes.zero.limb2
  destinationLimb3 :
    row.rdNext.limb3 =
      if row.rdNonzero then row.result.limb3 else WordBytes.zero.limb3
  nextPcResult : row.claimedNextPc = nextPc row.pc

def addiRetirement (row : AddiRow) : Retirement where
  nextPc := row.claimedNextPc
  write := architecturalWrite row.rd row.rdNext.word

def addiProgramTuple (row : AddiRow) : ProgramTuple where
  pc := row.pc
  opcodeId := 10
  rd := row.rd.toNat
  rs1 := row.rs1.toNat
  operand := (addiImmediate row.imm0 row.imm1 row.immSign).toNat

structure AddiRelations where
  program : ProgramTuple
  stateConsume : StateTuple
  stateEmit : StateTuple
  sourceConsume : RegisterTuple
  sourceEmit : RegisterTuple
  destinationConsume : RegisterTuple
  destinationEmit : RegisterTuple
deriving DecidableEq, Repr

def addiRelations (row : AddiRow) : AddiRelations where
  program := addiProgramTuple row
  stateConsume := { pc := row.pc, clock := row.clock }
  stateEmit := { pc := nextPc row.pc, clock := row.clock + 1 }
  sourceConsume := {
    addr := row.rs1
    clock := row.rs1PreviousClock
    value := row.rs1Previous.word
  }
  sourceEmit := {
    addr := row.rs1
    clock := accessClock row.clock 1
    value := row.rs1Next.word
  }
  destinationConsume := {
    addr := row.rd
    clock := row.rdPreviousClock
    value := row.rdPrevious.word
  }
  destinationEmit := {
    addr := row.rd
    clock := accessClock row.clock 2
    value := row.rdNext.word
  }

end RiscvRefinement.Air.Generated
