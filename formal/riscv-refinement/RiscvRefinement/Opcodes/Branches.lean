import RiscvRefinement.Air.Bridge.Branches

/-!
# RV32I branch retirement refinement

The six branch opcodes share one normalized retirement shape: choose the
signed-immediate target or `pc + 4`, write no register, and touch no memory.
The AIR bridges compute the decision from the typed source words and expose
the exact ordered production lookups.
-/

namespace RiscvRefinement.Opcodes.Branches

open RiscvRefinement

namespace Eq

abbrev Row := Air.Bridge.Branches.Eq.Row
abbrev Witness := Air.Bridge.Branches.Eq.Witness
abbrev Acceptance := Air.Bridge.Branches.Eq.Acceptance
abbrev Admission := Air.Bridge.Branches.Eq.admission

def word (row : Row) : InstructionWord :=
  Decode.encodeBranch row.kind.decode row.immediateEncoded row.rs2 row.rs1

def execute (row : Row) : Retirement where
  nextPc :=
    Air.Bridge.Branches.selectedPc
      row.pc row.immediateEncoded
      (Air.Bridge.Branches.Eq.taken row)
  write := none

def expectedTaken (row : Row) : Bool :=
  match row.kind with
  | .beq => decide (row.rs1Value.word = row.rs2Value.word)
  | .bne => decide (row.rs1Value.word ≠ row.rs2Value.word)

theorem decisionIsArchitectural (row : Row) :
    Air.Bridge.Branches.Eq.taken row = expectedTaken row := by
  cases row.kind <;>
    simp [
      Air.Bridge.Branches.Eq.taken,
      Air.Bridge.Branches.Eq.equal,
      expectedTaken,
    ] <;>
    rfl

structure Refinement (row : Row) (witness : Witness row) : Prop where
  production :
    Air.Bridge.Branches.Eq.ProductionRefinement row witness
  decode :
    Decode.isBranch row.kind.decode (word row) = true ∧
      Decode.decodeBImmediate (word row) =
        Decode.branchImmediate row.immediateEncoded ∧
      Decode.decodeRs2 (word row) = row.rs2 ∧
      Decode.decodeRs1 (word row) = row.rs1
  decision :
    Air.Bridge.Branches.Eq.taken row = expectedTaken row
  retirement :
    execute row = {
      nextPc :=
        Air.Bridge.Branches.selectedPc
          row.pc row.immediateEncoded (expectedTaken row)
      write := none
      read := none
      store := none
    }
  exactProgramTuple :
    (Air.Bridge.Branches.Eq.programLookup row).tuple = #[
      Air.Bridge.Branches.bitVecM31 row.pc,
      M31.reduce row.kind.manifestId,
      Air.Bridge.Branches.bitVecM31 row.rs1,
      Air.Bridge.Branches.bitVecM31 row.rs2,
      Air.Bridge.Branches.immediateField row.immediateEncoded
    ]
  noRegisterOrMemoryEffect :
    (execute row).write = none ∧
      (execute row).read = none ∧
      (execute row).store = none

theorem refines
    (row : Row)
    (witness : Witness row)
    (admission : Admission row)
    (accepted : Acceptance row witness) :
    Refinement row witness := by
  refine {
    production :=
      Air.Bridge.Branches.Eq.sound row witness admission accepted
    decode := ?_
    decision := decisionIsArchitectural row
    retirement := ?_
    exactProgramTuple := rfl
    noRegisterOrMemoryEffect := by simp [execute]
  }
  · exact
      Decode.encode_branch_is_canonical
        row.kind.decode row.immediateEncoded row.rs2 row.rs1
  · simp [execute, decisionIsArchitectural row]

theorem takenAndFallthroughRefine (kind : Air.Bridge.Branches.Eq.Kind) :
    (∃ row witness,
      Admission row ∧ Acceptance row witness ∧
        Refinement row witness ∧ expectedTaken row = true) ∧
    (∃ row witness,
      Admission row ∧ Acceptance row witness ∧
        Refinement row witness ∧ expectedTaken row = false) := by
  constructor
  · refine ⟨Air.Bridge.Branches.Eq.exampleRow kind true,
      Air.Bridge.Branches.Eq.exampleWitness kind true,
      Air.Bridge.Branches.Eq.exampleAdmission kind true,
      Air.Bridge.Branches.Eq.exampleAcceptance kind true,
      refines _ _
        (Air.Bridge.Branches.Eq.exampleAdmission kind true)
        (Air.Bridge.Branches.Eq.exampleAcceptance kind true), ?_⟩
    rw [← decisionIsArchitectural]
    exact Air.Bridge.Branches.Eq.exampleTaken kind true
  · refine ⟨Air.Bridge.Branches.Eq.exampleRow kind false,
      Air.Bridge.Branches.Eq.exampleWitness kind false,
      Air.Bridge.Branches.Eq.exampleAdmission kind false,
      Air.Bridge.Branches.Eq.exampleAcceptance kind false,
      refines _ _
        (Air.Bridge.Branches.Eq.exampleAdmission kind false)
        (Air.Bridge.Branches.Eq.exampleAcceptance kind false), ?_⟩
    rw [← decisionIsArchitectural]
    exact Air.Bridge.Branches.Eq.exampleTaken kind false

end Eq

namespace Lt

abbrev Row := Air.Bridge.Branches.Lt.Row
abbrev Witness := Air.Bridge.Branches.Lt.Witness
abbrev Acceptance := Air.Bridge.Branches.Lt.Acceptance
abbrev Admission := Air.Bridge.Branches.Lt.admission

def word (row : Row) : InstructionWord :=
  Decode.encodeBranch row.kind.decode row.immediateEncoded row.rs2 row.rs1

def execute (row : Row) : Retirement where
  nextPc :=
    Air.Bridge.Branches.selectedPc
      row.pc row.immediateEncoded
      (Air.Bridge.Branches.Lt.taken row)
  write := none

def expectedLess (row : Row) : Bool :=
  if row.kind.signed
  then
    Air.Bridge.Branches.Lt.signedLess
      row.rs1Value.word row.rs2Value.word
  else decide (row.rs1Value.word.toNat < row.rs2Value.word.toNat)

def expectedTaken (row : Row) : Bool :=
  if row.kind.lessOpcode then expectedLess row else !expectedLess row

theorem comparisonIsArchitectural (row : Row) :
    Air.Bridge.Branches.Lt.less row = expectedLess row := rfl

theorem decisionIsArchitectural (row : Row) :
    Air.Bridge.Branches.Lt.taken row = expectedTaken row := rfl

structure Refinement (row : Row) (witness : Witness row) : Prop where
  production :
    Air.Bridge.Branches.Lt.ProductionRefinement row witness
  decode :
    Decode.isBranch row.kind.decode (word row) = true ∧
      Decode.decodeBImmediate (word row) =
        Decode.branchImmediate row.immediateEncoded ∧
      Decode.decodeRs2 (word row) = row.rs2 ∧
      Decode.decodeRs1 (word row) = row.rs1
  comparison :
    Air.Bridge.Branches.Lt.less row = expectedLess row
  decision :
    Air.Bridge.Branches.Lt.taken row = expectedTaken row
  retirement :
    execute row = {
      nextPc :=
        Air.Bridge.Branches.selectedPc
          row.pc row.immediateEncoded (expectedTaken row)
      write := none
      read := none
      store := none
    }
  exactProgramTuple :
    (Air.Bridge.Branches.Lt.programLookup row).tuple = #[
      Air.Bridge.Branches.bitVecM31 row.pc,
      M31.reduce row.kind.manifestId,
      Air.Bridge.Branches.bitVecM31 row.rs1,
      Air.Bridge.Branches.bitVecM31 row.rs2,
      Air.Bridge.Branches.immediateField row.immediateEncoded
    ]
  noRegisterOrMemoryEffect :
    (execute row).write = none ∧
      (execute row).read = none ∧
      (execute row).store = none

theorem refines
    (row : Row)
    (witness : Witness row)
    (admission : Admission row)
    (accepted : Acceptance row witness) :
    Refinement row witness := by
  refine {
    production :=
      Air.Bridge.Branches.Lt.sound row witness admission accepted
    decode := ?_
    comparison := comparisonIsArchitectural row
    decision := decisionIsArchitectural row
    retirement := rfl
    exactProgramTuple := rfl
    noRegisterOrMemoryEffect := by simp [execute]
  }
  exact
    Decode.encode_branch_is_canonical
      row.kind.decode row.immediateEncoded row.rs2 row.rs1

theorem takenAndFallthroughRefine (kind : Air.Bridge.Branches.Lt.Kind) :
    (∃ row witness,
      Admission row ∧ Acceptance row witness ∧
        Refinement row witness ∧ expectedTaken row = true) ∧
    (∃ row witness,
      Admission row ∧ Acceptance row witness ∧
        Refinement row witness ∧ expectedTaken row = false) := by
  constructor
  · refine ⟨Air.Bridge.Branches.Lt.exampleRow kind true,
      Air.Bridge.Branches.Lt.exampleWitness kind true,
      Air.Bridge.Branches.Lt.exampleAdmission kind true,
      Air.Bridge.Branches.Lt.exampleAcceptance kind true,
      refines _ _
        (Air.Bridge.Branches.Lt.exampleAdmission kind true)
        (Air.Bridge.Branches.Lt.exampleAcceptance kind true), ?_⟩
    exact Air.Bridge.Branches.Lt.exampleTaken kind true
  · refine ⟨Air.Bridge.Branches.Lt.exampleRow kind false,
      Air.Bridge.Branches.Lt.exampleWitness kind false,
      Air.Bridge.Branches.Lt.exampleAdmission kind false,
      Air.Bridge.Branches.Lt.exampleAcceptance kind false,
      refines _ _
        (Air.Bridge.Branches.Lt.exampleAdmission kind false)
        (Air.Bridge.Branches.Lt.exampleAcceptance kind false), ?_⟩
    exact Air.Bridge.Branches.Lt.exampleTaken kind false

end Lt

end RiscvRefinement.Opcodes.Branches
