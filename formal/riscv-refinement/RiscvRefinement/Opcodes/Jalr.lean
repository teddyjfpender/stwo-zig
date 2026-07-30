import RiscvRefinement.Air.Bridge.Jalr

/-!
# JALR production refinement

This module composes the exact production AIR certificate with canonical
instruction decode and a pre-state environment.  In particular, the source
operand is the pre-write register value even when `rd = rs1`; the link write
therefore cannot feed back into target calculation.
-/

namespace RiscvRefinement.Opcodes.Jalr

open RiscvRefinement

abbrev Row := Air.Bridge.Jalr.Row
abbrev Witness := Air.Bridge.Jalr.Witness
abbrev Admission := Air.Bridge.Jalr.Admission
abbrev Acceptance := Air.Bridge.Jalr.Acceptance

def word (row : Row) : InstructionWord :=
  Decode.encodeJalr row.immediate row.rs1 row.rd

def execute
    (pc source : Word)
    (rd : RegisterIndex)
    (immediate : BitVec 12) : Retirement where
  nextPc := Air.Bridge.Jalr.jumpTarget source immediate
  write := architecturalWrite rd (RiscvRefinement.nextPc pc)

def airRetirement (row : Row) : Retirement where
  nextPc := row.target.word
  write := architecturalWrite row.rd row.rdNext.word

def programTuple (row : Row) : ProgramTuple where
  pc := row.pc
  opcodeId := 34
  rd := row.rd.toNat
  rs1 := row.rs1.toNat
  operand := row.immediate.toNat

structure Environment (row : Row) where
  pre : PreState
  pcBinds : row.pc = pre.pc
  sourceBinds : row.rs1Previous.word = pre.registers row.rs1
  destinationBinds : row.rdPrevious.word = pre.registers row.rd

theorem jalr_selectorAccepted
    (row : Row)
    (witness : Witness row)
    (accepted : Acceptance row witness) :
    (Air.Bridge.Jalr.evaluation row witness).activeSelectorsAccepted =
      true :=
  accepted.selectors

theorem jalr_exactProgramTuple (row : Row) :
    (Air.Bridge.Jalr.programLookup row).tuple = #[
      Air.Bridge.Jalr.bitVecM31 row.pc,
      M31.reduce 34,
      Air.Bridge.Jalr.bitVecM31 row.rd,
      Air.Bridge.Jalr.bitVecM31 row.rs1,
      Air.Bridge.Jalr.immediateField row.immediate
    ] := by
  rfl

theorem jalr_exactLookupProjection
    (row : Row)
    (witness : Witness row) :
    Air.Bridge.Jalr.ExactLookups row witness :=
  Air.Bridge.Jalr.exactLookups row witness

theorem exactProgramTuple (row : Row) :
    programTuple row = {
      pc := row.pc
      opcodeId := 34
      rd := row.rd.toNat
      rs1 := row.rs1.toNat
      operand := row.immediate.toNat
    } := by
  rfl

structure Refinement
    (row : Row)
    (witness : Witness row)
    (environment : Environment row) : Prop where
  production : Air.Bridge.Jalr.ProductionRefinement row witness
  decode :
    Decode.isJalr (word row) = true ∧
      Decode.decodeIImmediate (word row) = row.immediate ∧
      Decode.decodeRs1 (word row) = row.rs1 ∧
      Decode.decodeRd (word row) = row.rd
  program :
    programTuple row = {
      pc := row.pc
      opcodeId := 34
      rd := row.rd.toNat
      rs1 := row.rs1.toNat
      operand := row.immediate.toNat
    }
  exactProgramLookup :
    (Air.Bridge.Jalr.evaluation row witness).lookup? 23 =
      some (Air.Bridge.Jalr.programLookup row)
  sourceBeforeDestination :
    row.rs1Previous.word = environment.pre.registers row.rs1 ∧
      row.rs1Next.word = environment.pre.registers row.rs1
  signedImmediate :
    (Air.Bridge.Jalr.immediateBytes row).word =
      BitVec.signExtend 32 row.immediate
  wrappedAddition :
    row.target.word + BitVec.ofNat 32 row.targetLsb.toNat =
      Air.Bridge.Jalr.unalignedTarget
        (environment.pre.registers row.rs1) row.immediate
  target :
    row.target.word =
      Air.Bridge.Jalr.jumpTarget
        (environment.pre.registers row.rs1) row.immediate
  bitZeroCleared : row.target.word.toNat % 2 = 0
  successfulAlignment : row.target.word.toNat % 4 = 0
  destination :
    row.rdNext.word =
      architecturalValue row.rd
        (RiscvRefinement.nextPc environment.pre.pc)
  retirement :
    airRetirement row =
      execute environment.pre.pc
        (environment.pre.registers row.rs1) row.rd row.immediate
  zeroRegister :
    row.rd = zeroRegister → (airRetirement row).write = none
  aliasReadBeforeWrite :
    row.rd = row.rs1 →
      (airRetirement row).nextPc =
        Air.Bridge.Jalr.jumpTarget
          (environment.pre.registers row.rd) row.immediate
  noMemoryEffect :
    (airRetirement row).read = none ∧
      (airRetirement row).store = none

theorem refines
    (row : Row)
    (witness : Witness row)
    (environment : Environment row)
    (admission : Admission row)
    (accepted : Acceptance row witness) :
    Refinement row witness environment := by
  have production :=
    Air.Bridge.Jalr.sound row witness admission accepted
  have sourceNext :
      row.rs1Next.word = environment.pre.registers row.rs1 := by
    rw [production.sourceValue, environment.sourceBinds]
  have wrapped :
      row.target.word + BitVec.ofNat 32 row.targetLsb.toNat =
        Air.Bridge.Jalr.unalignedTarget
          (environment.pre.registers row.rs1) row.immediate := by
    rw [← environment.sourceBinds]
    exact production.wrappedAddition
  have target :
      row.target.word =
        Air.Bridge.Jalr.jumpTarget
          (environment.pre.registers row.rs1) row.immediate := by
    rw [← environment.sourceBinds]
    exact production.target
  have destination :
      row.rdNext.word =
        architecturalValue row.rd
          (RiscvRefinement.nextPc environment.pre.pc) := by
    rw [← environment.pcBinds]
    exact production.destination
  have retirement :
      airRetirement row =
        execute environment.pre.pc
          (environment.pre.registers row.rs1) row.rd row.immediate := by
    simp only [airRetirement, execute]
    rw [
      target,
      destination,
      architecturalWrite_value,
    ]
  refine {
    production
    decode := Decode.encode_jalr_is_canonical row.immediate row.rs1 row.rd
    program := exactProgramTuple row
    exactProgramLookup := production.program
    sourceBeforeDestination := ⟨environment.sourceBinds, sourceNext⟩
    signedImmediate := production.signedImmediate
    wrappedAddition := wrapped
    target := target
    bitZeroCleared := by
      have aligned := production.targetAligned
      omega
    successfulAlignment := production.targetAligned
    destination := destination
    retirement := retirement
    zeroRegister := ?_
    aliasReadBeforeWrite := ?_
    noMemoryEffect := by simp [airRetirement]
  }
  · intro zero
    simp [airRetirement, zero, architecturalWrite]
  · intro alias
    rw [retirement]
    simp only [execute]
    rw [alias]

theorem jalr_refines
    (row : Row)
    (witness : Witness row)
    (environment : Environment row)
    (admission : Admission row)
    (accepted : Acceptance row witness) :
    Refinement row witness environment :=
  refines row witness environment admission accepted

def examplePreState : PreState where
  pc := BitVec.ofNat 32 0x1000
  registers := fun index =>
    if index = BitVec.ofNat 5 2
    then BitVec.ofNat 32 101
    else zeroWord
  x0IsZero := by decide

def exampleEnvironment :
    Environment Air.Bridge.Jalr.exampleRow where
  pre := examplePreState
  pcBinds := by decide
  sourceBinds := by decide
  destinationBinds := by decide

def zeroDestinationEnvironment :
    Environment Air.Bridge.Jalr.zeroDestinationRow where
  pre := examplePreState
  pcBinds := by decide
  sourceBinds := by decide
  destinationBinds := by decide

def sourceAliasPreState : PreState where
  pc := BitVec.ofNat 32 0x1000
  registers := fun index =>
    if index = BitVec.ofNat 5 1
    then BitVec.ofNat 32 101
    else zeroWord
  x0IsZero := by decide

def sourceAliasEnvironment :
    Environment Air.Bridge.Jalr.sourceAliasRow where
  pre := sourceAliasPreState
  pcBinds := by decide
  sourceBinds := by decide
  destinationBinds := by decide

theorem jalr_nonvacuous :
    ∃ (row : Row) (witness : Witness row) (environment : Environment row),
      Admission row ∧ Acceptance row witness ∧
        Refinement row witness environment :=
  ⟨
    Air.Bridge.Jalr.exampleRow,
    Air.Bridge.Jalr.exampleWitness,
    exampleEnvironment,
    Air.Bridge.Jalr.exampleAdmission,
    Air.Bridge.Jalr.exampleAcceptance,
    refines _ _ _ Air.Bridge.Jalr.exampleAdmission
      Air.Bridge.Jalr.exampleAcceptance
  ⟩

theorem jalr_zero_destination_nonvacuous :
    ∃ (row : Row) (witness : Witness row) (environment : Environment row),
      Admission row ∧ Acceptance row witness ∧
        Refinement row witness environment ∧
          row.rd = zeroRegister :=
  ⟨
    Air.Bridge.Jalr.zeroDestinationRow,
    Air.Bridge.Jalr.zeroDestinationWitness,
    zeroDestinationEnvironment,
    Air.Bridge.Jalr.zeroDestinationAdmission,
    Air.Bridge.Jalr.zeroDestinationAcceptance,
    refines _ _ _ Air.Bridge.Jalr.zeroDestinationAdmission
      Air.Bridge.Jalr.zeroDestinationAcceptance,
    rfl
  ⟩

theorem jalr_source_alias_nonvacuous :
    ∃ (row : Row) (witness : Witness row) (environment : Environment row),
      Admission row ∧ Acceptance row witness ∧
        Refinement row witness environment ∧
          row.rd = row.rs1 :=
  ⟨
    Air.Bridge.Jalr.sourceAliasRow,
    Air.Bridge.Jalr.sourceAliasWitness,
    sourceAliasEnvironment,
    Air.Bridge.Jalr.sourceAliasAdmission,
    Air.Bridge.Jalr.sourceAliasAcceptance,
    refines _ _ _ Air.Bridge.Jalr.sourceAliasAdmission
      Air.Bridge.Jalr.sourceAliasAcceptance,
    rfl
  ⟩

end RiscvRefinement.Opcodes.Jalr
