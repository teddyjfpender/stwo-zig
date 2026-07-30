import RiscvRefinement.Air.Bridge.BaseAluReg

/-!
# RV32I base register-ALU production refinement

ADD, SUB, XOR, OR, and AND are connected here from their exact generated AIR
rows to canonical R-type decode and normalized architectural retirement.
-/

namespace RiscvRefinement.Opcodes.BaseAluReg

open RiscvRefinement

abbrev Op := Decode.BaseAluRegOp
abbrev Row := Air.Bridge.BaseAluReg.Row
abbrev Witness := Air.Bridge.BaseAluReg.Witness
abbrev Admission := Air.Bridge.BaseAluReg.Admission
abbrev Acceptance := Air.Bridge.BaseAluReg.Acceptance

def word (op : Op) (row : Row) : InstructionWord :=
  Decode.encodeBaseAluReg op row.rs2 row.rs1 row.rd

def execute
    (op : Op)
    (pc source1 source2 : Word)
    (rd : RegisterIndex) : Retirement where
  nextPc := RiscvRefinement.nextPc pc
  write :=
    architecturalWrite rd
      (Air.Bridge.BaseAluReg.executeValue op source1 source2)

def airRetirement (row : Row) : Retirement where
  nextPc := RiscvRefinement.nextPc row.pc
  write := architecturalWrite row.rd row.rdNext.word

def programTuple (op : Op) (row : Row) : ProgramTuple where
  pc := row.pc
  opcodeId := Decode.baseAluRegOpcodeId op
  rd := row.rd.toNat
  rs1 := row.rs1.toNat
  operand := row.rs2.toNat

structure Environment (row : Row) where
  pre : PreState
  pcBinds : row.pc = pre.pc
  source1Binds : row.rs1Previous.word = pre.registers row.rs1
  source2Binds : row.rs2Previous.word = pre.registers row.rs2
  destinationBinds : row.rdPrevious.word = pre.registers row.rd

theorem exactProgramTuple (op : Op) (row : Row) :
    programTuple op row = {
      pc := row.pc
      opcodeId := Decode.baseAluRegOpcodeId op
      rd := row.rd.toNat
      rs1 := row.rs1.toNat
      operand := row.rs2.toNat
    } := rfl

theorem add_selectorAccepted
    (row : Row)
    (witness : Witness row) :
    (Air.Bridge.BaseAluReg.evaluation .add row witness).activeSelectorsAccepted =
      true :=
  Air.Bridge.BaseAluReg.selectorAccepted .add row witness

theorem sub_selectorAccepted
    (row : Row)
    (witness : Witness row) :
    (Air.Bridge.BaseAluReg.evaluation .sub row witness).activeSelectorsAccepted =
      true :=
  Air.Bridge.BaseAluReg.selectorAccepted .sub row witness

theorem xor_selectorAccepted
    (row : Row)
    (witness : Witness row) :
    (Air.Bridge.BaseAluReg.evaluation .xor row witness).activeSelectorsAccepted =
      true :=
  Air.Bridge.BaseAluReg.selectorAccepted .xor row witness

theorem or_selectorAccepted
    (row : Row)
    (witness : Witness row) :
    (Air.Bridge.BaseAluReg.evaluation .or row witness).activeSelectorsAccepted =
      true :=
  Air.Bridge.BaseAluReg.selectorAccepted .or row witness

theorem and_selectorAccepted
    (row : Row)
    (witness : Witness row) :
    (Air.Bridge.BaseAluReg.evaluation .and row witness).activeSelectorsAccepted =
      true :=
  Air.Bridge.BaseAluReg.selectorAccepted .and row witness

theorem add_exactProgramTuple (row : Row) :
    (Air.Bridge.BaseAluReg.programLookup .add row).tuple = #[
      Air.Bridge.BaseAluReg.bitVecM31 row.pc,
      M31.reduce 0,
      Air.Bridge.BaseAluReg.bitVecM31 row.rd,
      Air.Bridge.BaseAluReg.bitVecM31 row.rs1,
      Air.Bridge.BaseAluReg.bitVecM31 row.rs2
    ] := by
  rfl

theorem sub_exactProgramTuple (row : Row) :
    (Air.Bridge.BaseAluReg.programLookup .sub row).tuple = #[
      Air.Bridge.BaseAluReg.bitVecM31 row.pc,
      M31.reduce 1,
      Air.Bridge.BaseAluReg.bitVecM31 row.rd,
      Air.Bridge.BaseAluReg.bitVecM31 row.rs1,
      Air.Bridge.BaseAluReg.bitVecM31 row.rs2
    ] := by
  rfl

theorem xor_exactProgramTuple (row : Row) :
    (Air.Bridge.BaseAluReg.programLookup .xor row).tuple = #[
      Air.Bridge.BaseAluReg.bitVecM31 row.pc,
      M31.reduce 5,
      Air.Bridge.BaseAluReg.bitVecM31 row.rd,
      Air.Bridge.BaseAluReg.bitVecM31 row.rs1,
      Air.Bridge.BaseAluReg.bitVecM31 row.rs2
    ] := by
  rfl

theorem or_exactProgramTuple (row : Row) :
    (Air.Bridge.BaseAluReg.programLookup .or row).tuple = #[
      Air.Bridge.BaseAluReg.bitVecM31 row.pc,
      M31.reduce 8,
      Air.Bridge.BaseAluReg.bitVecM31 row.rd,
      Air.Bridge.BaseAluReg.bitVecM31 row.rs1,
      Air.Bridge.BaseAluReg.bitVecM31 row.rs2
    ] := by
  rfl

theorem and_exactProgramTuple (row : Row) :
    (Air.Bridge.BaseAluReg.programLookup .and row).tuple = #[
      Air.Bridge.BaseAluReg.bitVecM31 row.pc,
      M31.reduce 9,
      Air.Bridge.BaseAluReg.bitVecM31 row.rd,
      Air.Bridge.BaseAluReg.bitVecM31 row.rs1,
      Air.Bridge.BaseAluReg.bitVecM31 row.rs2
    ] := by
  rfl

/--
The selector-specific exact lookup certificates below expose the complete
generated projection, not only the five-field program tuple.  In particular,
the returned production refinement contains the program, state, both source
chains, four bitwise requests, result range checks, and destination chain at
their exact generated ordinals.
-/
theorem add_exactLookupProjection
    (row : Row) (witness : Witness row)
    (admission : Admission row) (accepted : Acceptance .add row witness) :
    Air.Bridge.BaseAluReg.ProductionRefinement .add row witness :=
  Air.Bridge.BaseAluReg.sound .add row witness admission accepted

theorem sub_exactLookupProjection
    (row : Row) (witness : Witness row)
    (admission : Admission row) (accepted : Acceptance .sub row witness) :
    Air.Bridge.BaseAluReg.ProductionRefinement .sub row witness :=
  Air.Bridge.BaseAluReg.sound .sub row witness admission accepted

theorem xor_exactLookupProjection
    (row : Row) (witness : Witness row)
    (admission : Admission row) (accepted : Acceptance .xor row witness) :
    Air.Bridge.BaseAluReg.ProductionRefinement .xor row witness :=
  Air.Bridge.BaseAluReg.sound .xor row witness admission accepted

theorem or_exactLookupProjection
    (row : Row) (witness : Witness row)
    (admission : Admission row) (accepted : Acceptance .or row witness) :
    Air.Bridge.BaseAluReg.ProductionRefinement .or row witness :=
  Air.Bridge.BaseAluReg.sound .or row witness admission accepted

theorem and_exactLookupProjection
    (row : Row) (witness : Witness row)
    (admission : Admission row) (accepted : Acceptance .and row witness) :
    Air.Bridge.BaseAluReg.ProductionRefinement .and row witness :=
  Air.Bridge.BaseAluReg.sound .and row witness admission accepted

structure Refinement
    (op : Op)
    (row : Row)
    (witness : Witness row)
    (environment : Environment row) : Prop where
  production : Air.Bridge.BaseAluReg.ProductionRefinement op row witness
  decode :
    Decode.isBaseAluReg op (word op row) = true ∧
      Decode.decodeRs2 (word op row) = row.rs2 ∧
      Decode.decodeRs1 (word op row) = row.rs1 ∧
      Decode.decodeRd (word op row) = row.rd
  program :
    programTuple op row = {
      pc := row.pc
      opcodeId := Decode.baseAluRegOpcodeId op
      rd := row.rd.toNat
      rs1 := row.rs1.toNat
      operand := row.rs2.toNat
    }
  exactProgramLookup :
    (Air.Bridge.BaseAluReg.evaluation op row witness).lookup? 30 =
      some (Air.Bridge.BaseAluReg.programLookup op row)
  source1 :
    row.rs1Next.word = environment.pre.registers row.rs1
  source2 :
    row.rs2Next.word = environment.pre.registers row.rs2
  destination :
    row.rdNext.word =
      architecturalValue row.rd
        (Air.Bridge.BaseAluReg.executeValue op
          (environment.pre.registers row.rs1)
          (environment.pre.registers row.rs2))
  retirement :
    airRetirement row =
      execute op environment.pre.pc
        (environment.pre.registers row.rs1)
        (environment.pre.registers row.rs2) row.rd
  zeroRegister :
    row.rd = zeroRegister → (airRetirement row).write = none
  noMemoryEffect :
    (airRetirement row).read = none ∧
      (airRetirement row).store = none

theorem refines
    (op : Op)
    (row : Row)
    (witness : Witness row)
    (environment : Environment row)
    (admission : Admission row)
    (accepted : Acceptance op row witness) :
    Refinement op row witness environment := by
  have production :=
    Air.Bridge.BaseAluReg.sound op row witness admission accepted
  have result :
      row.result.word =
        Air.Bridge.BaseAluReg.executeValue op
          (environment.pre.registers row.rs1)
          (environment.pre.registers row.rs2) := by
    rw [← environment.source1Binds, ← environment.source2Binds]
    exact production.resultValue
  have destination :
      row.rdNext.word =
        architecturalValue row.rd
          (Air.Bridge.BaseAluReg.executeValue op
            (environment.pre.registers row.rs1)
            (environment.pre.registers row.rs2)) := by
    rw [production.destinationValue, result]
  refine {
    production
    decode :=
      Decode.encode_base_alu_reg_is_canonical
        op row.rs2 row.rs1 row.rd
    program := exactProgramTuple op row
    exactProgramLookup := production.program
    source1 := by
      rw [production.source1Value, environment.source1Binds]
    source2 := by
      rw [production.source2Value, environment.source2Binds]
    destination
    retirement := ?_
    zeroRegister := ?_
    noMemoryEffect := by simp [airRetirement]
  }
  · simp only [airRetirement, execute]
    rw [environment.pcBinds, destination, architecturalWrite_value]
  · intro zero
    simp [airRetirement, zero, architecturalWrite]

theorem add_refines
    (row : Row) (witness : Witness row) (environment : Environment row)
    (admission : Admission row) (accepted : Acceptance .add row witness) :
    Refinement .add row witness environment :=
  refines .add row witness environment admission accepted

theorem sub_refines
    (row : Row) (witness : Witness row) (environment : Environment row)
    (admission : Admission row) (accepted : Acceptance .sub row witness) :
    Refinement .sub row witness environment :=
  refines .sub row witness environment admission accepted

theorem xor_refines
    (row : Row) (witness : Witness row) (environment : Environment row)
    (admission : Admission row) (accepted : Acceptance .xor row witness) :
    Refinement .xor row witness environment :=
  refines .xor row witness environment admission accepted

theorem or_refines
    (row : Row) (witness : Witness row) (environment : Environment row)
    (admission : Admission row) (accepted : Acceptance .or row witness) :
    Refinement .or row witness environment :=
  refines .or row witness environment admission accepted

theorem and_refines
    (row : Row) (witness : Witness row) (environment : Environment row)
    (admission : Admission row) (accepted : Acceptance .and row witness) :
    Refinement .and row witness environment :=
  refines .and row witness environment admission accepted

def zeroPreState : PreState where
  pc := BitVec.ofNat 32 0x1000
  registers := fun _ => zeroWord
  x0IsZero := rfl

def zeroEnvironment
    (zeroDestination : Bool)
    (rs1 rs2 : RegisterIndex) :
    Environment (Air.Bridge.BaseAluReg.zeroRow zeroDestination rs1 rs2) where
  pre := zeroPreState
  pcBinds := rfl
  source1Binds := WordBytes.zero_word
  source2Binds := WordBytes.zero_word
  destinationBinds := WordBytes.zero_word

theorem refinementNonvacuous (op : Op) :
    ∃ (row : Row) (witness : Witness row) (environment : Environment row),
      Admission row ∧ Acceptance op row witness ∧
        Refinement op row witness environment := by
  let rs1 : RegisterIndex := BitVec.ofNat 5 2
  let rs2 : RegisterIndex := BitVec.ofNat 5 3
  exact ⟨
    Air.Bridge.BaseAluReg.zeroRow false rs1 rs2,
    Air.Bridge.BaseAluReg.zeroWitness false rs1 rs2,
    zeroEnvironment false rs1 rs2,
    Air.Bridge.BaseAluReg.zeroAdmission false rs1 rs2,
    Air.Bridge.BaseAluReg.zeroAcceptance op false rs1 rs2,
    refines op _ _ _ (Air.Bridge.BaseAluReg.zeroAdmission false rs1 rs2)
      (Air.Bridge.BaseAluReg.zeroAcceptance op false rs1 rs2)
  ⟩

theorem zeroDestinationRefinementNonvacuous (op : Op) :
    ∃ (row : Row) (witness : Witness row) (environment : Environment row),
      Admission row ∧ Acceptance op row witness ∧
        Refinement op row witness environment ∧ row.rd = zeroRegister := by
  let rs1 : RegisterIndex := BitVec.ofNat 5 2
  let rs2 : RegisterIndex := BitVec.ofNat 5 3
  exact ⟨
    Air.Bridge.BaseAluReg.zeroRow true rs1 rs2,
    Air.Bridge.BaseAluReg.zeroWitness true rs1 rs2,
    zeroEnvironment true rs1 rs2,
    Air.Bridge.BaseAluReg.zeroAdmission true rs1 rs2,
    Air.Bridge.BaseAluReg.zeroAcceptance op true rs1 rs2,
    refines op _ _ _ (Air.Bridge.BaseAluReg.zeroAdmission true rs1 rs2)
      (Air.Bridge.BaseAluReg.zeroAcceptance op true rs1 rs2),
    by rfl
  ⟩

theorem source1AliasRefinementNonvacuous (op : Op) :
    ∃ (row : Row) (witness : Witness row) (environment : Environment row),
      Admission row ∧ Acceptance op row witness ∧
        Refinement op row witness environment ∧ row.rd = row.rs1 := by
  let rs1 : RegisterIndex := BitVec.ofNat 5 1
  let rs2 : RegisterIndex := BitVec.ofNat 5 2
  exact ⟨
    Air.Bridge.BaseAluReg.zeroRow false rs1 rs2,
    Air.Bridge.BaseAluReg.zeroWitness false rs1 rs2,
    zeroEnvironment false rs1 rs2,
    Air.Bridge.BaseAluReg.zeroAdmission false rs1 rs2,
    Air.Bridge.BaseAluReg.zeroAcceptance op false rs1 rs2,
    refines op _ _ _ (Air.Bridge.BaseAluReg.zeroAdmission false rs1 rs2)
      (Air.Bridge.BaseAluReg.zeroAcceptance op false rs1 rs2),
    by rfl
  ⟩

theorem source2AliasRefinementNonvacuous (op : Op) :
    ∃ (row : Row) (witness : Witness row) (environment : Environment row),
      Admission row ∧ Acceptance op row witness ∧
        Refinement op row witness environment ∧ row.rd = row.rs2 := by
  let rs1 : RegisterIndex := BitVec.ofNat 5 2
  let rs2 : RegisterIndex := BitVec.ofNat 5 1
  exact ⟨
    Air.Bridge.BaseAluReg.zeroRow false rs1 rs2,
    Air.Bridge.BaseAluReg.zeroWitness false rs1 rs2,
    zeroEnvironment false rs1 rs2,
    Air.Bridge.BaseAluReg.zeroAdmission false rs1 rs2,
    Air.Bridge.BaseAluReg.zeroAcceptance op false rs1 rs2,
    refines op _ _ _ (Air.Bridge.BaseAluReg.zeroAdmission false rs1 rs2)
      (Air.Bridge.BaseAluReg.zeroAcceptance op false rs1 rs2),
    by rfl
  ⟩

theorem sameSourceRefinementNonvacuous (op : Op) :
    ∃ (row : Row) (witness : Witness row) (environment : Environment row),
      Admission row ∧ Acceptance op row witness ∧
        Refinement op row witness environment ∧
        row.rs1 = row.rs2 ∧ row.rd ≠ row.rs1 := by
  let source : RegisterIndex := BitVec.ofNat 5 2
  exact ⟨
    Air.Bridge.BaseAluReg.zeroRow false source source,
    Air.Bridge.BaseAluReg.zeroWitness false source source,
    zeroEnvironment false source source,
    Air.Bridge.BaseAluReg.zeroAdmission false source source,
    Air.Bridge.BaseAluReg.zeroAcceptance op false source source,
    refines op _ _ _ (Air.Bridge.BaseAluReg.zeroAdmission false source source)
      (Air.Bridge.BaseAluReg.zeroAcceptance op false source source),
    by rfl,
    by decide
  ⟩

def addOverflowPreState : PreState where
  pc := Air.Bridge.BaseAluReg.addOverflowRow.pc
  registers := fun index =>
    if index = BitVec.ofNat 5 2
    then Air.Bridge.BaseAluReg.maxWordBytes.word
    else if index = BitVec.ofNat 5 3
    then Air.Bridge.BaseAluReg.oneWordBytes.word
    else zeroWord
  x0IsZero := by decide

def addOverflowEnvironment :
    Environment Air.Bridge.BaseAluReg.addOverflowRow where
  pre := addOverflowPreState
  pcBinds := rfl
  source1Binds := by decide
  source2Binds := by decide
  destinationBinds := by decide

theorem add_overflow_nonvacuous :
    Admission Air.Bridge.BaseAluReg.addOverflowRow ∧
      Acceptance .add Air.Bridge.BaseAluReg.addOverflowRow
        Air.Bridge.BaseAluReg.addOverflowWitness ∧
      Refinement .add Air.Bridge.BaseAluReg.addOverflowRow
        Air.Bridge.BaseAluReg.addOverflowWitness addOverflowEnvironment ∧
      Air.Bridge.BaseAluReg.addOverflowRow.rs1Previous.word +
          Air.Bridge.BaseAluReg.addOverflowRow.rs2Previous.word = zeroWord := by
  exact ⟨
    Air.Bridge.BaseAluReg.addOverflowAdmission,
    Air.Bridge.BaseAluReg.addOverflowAcceptance,
    refines .add _ _ addOverflowEnvironment
      Air.Bridge.BaseAluReg.addOverflowAdmission
      Air.Bridge.BaseAluReg.addOverflowAcceptance,
    by decide
  ⟩

def subBorrowPreState : PreState where
  pc := Air.Bridge.BaseAluReg.subBorrowRow.pc
  registers := fun index =>
    if index = BitVec.ofNat 5 3
    then Air.Bridge.BaseAluReg.oneWordBytes.word
    else zeroWord
  x0IsZero := by decide

def subBorrowEnvironment :
    Environment Air.Bridge.BaseAluReg.subBorrowRow where
  pre := subBorrowPreState
  pcBinds := rfl
  source1Binds := by decide
  source2Binds := by decide
  destinationBinds := by decide

theorem sub_borrow_nonvacuous :
    Admission Air.Bridge.BaseAluReg.subBorrowRow ∧
      Acceptance .sub Air.Bridge.BaseAluReg.subBorrowRow
        Air.Bridge.BaseAluReg.subBorrowWitness ∧
      Refinement .sub Air.Bridge.BaseAluReg.subBorrowRow
        Air.Bridge.BaseAluReg.subBorrowWitness subBorrowEnvironment ∧
      Air.Bridge.BaseAluReg.subBorrowRow.rs1Previous.word -
          Air.Bridge.BaseAluReg.subBorrowRow.rs2Previous.word =
        BitVec.ofNat 32 0xffffffff := by
  exact ⟨
    Air.Bridge.BaseAluReg.subBorrowAdmission,
    Air.Bridge.BaseAluReg.subBorrowAcceptance,
    refines .sub _ _ subBorrowEnvironment
      Air.Bridge.BaseAluReg.subBorrowAdmission
      Air.Bridge.BaseAluReg.subBorrowAcceptance,
    by decide
  ⟩

theorem add_nonvacuous :
    ∃ (row : Row) (witness : Witness row) (environment : Environment row),
      Admission row ∧ Acceptance .add row witness ∧
        Refinement .add row witness environment :=
  refinementNonvacuous .add

theorem sub_nonvacuous :
    ∃ (row : Row) (witness : Witness row) (environment : Environment row),
      Admission row ∧ Acceptance .sub row witness ∧
        Refinement .sub row witness environment :=
  refinementNonvacuous .sub

theorem xor_nonvacuous :
    ∃ (row : Row) (witness : Witness row) (environment : Environment row),
      Admission row ∧ Acceptance .xor row witness ∧
        Refinement .xor row witness environment :=
  refinementNonvacuous .xor

theorem or_nonvacuous :
    ∃ (row : Row) (witness : Witness row) (environment : Environment row),
      Admission row ∧ Acceptance .or row witness ∧
        Refinement .or row witness environment :=
  refinementNonvacuous .or

theorem and_nonvacuous :
    ∃ (row : Row) (witness : Witness row) (environment : Environment row),
      Admission row ∧ Acceptance .and row witness ∧
        Refinement .and row witness environment :=
  refinementNonvacuous .and

end RiscvRefinement.Opcodes.BaseAluReg
