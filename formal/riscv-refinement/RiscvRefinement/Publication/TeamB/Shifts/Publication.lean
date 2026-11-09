import RiscvRefinement.Publication.TeamB.Shifts.Relations

/-! Bounded shift publication proof owner: Publication. -/
namespace RiscvRefinement.Publication.TeamB.Shifts

open RiscvRefinement
open RiscvRefinement.Air
open RiscvRefinement.Air.Family
open RiscvRefinement.Air.Generated
open RiscvRefinement.Opcodes
open RiscvRefinement.Sail.Reviewed

def generatedProgramIdentity (program : LocalProgram) :
    ProgramIdentity where
  manifestId := program.source.opcodeSelector.manifestId
  mnemonic := program.source.opcodeSelector.mnemonic
  family := program.source.family
  contentDigest := program.source.contentDigest

def sllProgramIdentity : ProgramIdentity where
  manifestId := 2
  mnemonic := "sll"
  family := .shiftsReg
  contentDigest :=
    "52022ad041db36a5dd07b3da5dfca6ff4203f60d6199562deef32347af17aae5"

def srlProgramIdentity : ProgramIdentity where
  manifestId := 6
  mnemonic := "srl"
  family := .shiftsReg
  contentDigest :=
    "5c8ac19403807ea6c4b657d7b4a47473184c6423d8a8c7acb133c8e431791dd2"

def sraProgramIdentity : ProgramIdentity where
  manifestId := 7
  mnemonic := "sra"
  family := .shiftsReg
  contentDigest :=
    "04f196d6512eb3bcaa8a97a7f54becfc195a3dcead9f29940f713b9c76762450"

def slliProgramIdentity : ProgramIdentity where
  manifestId := 16
  mnemonic := "slli"
  family := .shiftsImm
  contentDigest :=
    "4c495eb6176d76116b74c946f9dae386bfb9928f2f3e191aa4d581f35d079db4"

def srliProgramIdentity : ProgramIdentity where
  manifestId := 17
  mnemonic := "srli"
  family := .shiftsImm
  contentDigest :=
    "eab44f64ec4d7ebe1f1f9ef1ec170e34bd2054760e4a1b19fb091d6b0ab33d38"

def sraiProgramIdentity : ProgramIdentity where
  manifestId := 18
  mnemonic := "srai"
  family := .shiftsImm
  contentDigest :=
    "b77fc84e0d48c224f819f15a0616f299c31df40d697d2486fe61e5c188f41e12"

structure ExactSelectorIdentity
    (program : LocalProgram)
    (expected : ProgramIdentity) : Prop where
  exactProgram : generatedProgramIdentity program = expected
  familyAdmission :
    program.source.family.validOpcode
      program.source.opcodeSelector.manifestId
      program.source.opcodeSelector.mnemonic = true
  manifestUnique :
    actualProgramIdentities.filter
        (fun identity =>
          decide (identity.manifestId = expected.manifestId)) =
      [expected]
  mnemonicUnique :
    actualProgramIdentities.filter
        (fun identity =>
          decide (identity.mnemonic = expected.mnemonic)) =
      [expected]

set_option maxRecDepth 30000 in
theorem sll_exactSelectorIdentity :
    ExactSelectorIdentity Programs.sll sllProgramIdentity := by
  refine {
    exactProgram := rfl
    familyAdmission := by decide
    manifestUnique := by
      rw [exactProductionProgramIdentities]
      decide
    mnemonicUnique := by
      rw [exactProductionProgramIdentities]
      decide
  }

set_option maxRecDepth 30000 in
theorem srl_exactSelectorIdentity :
    ExactSelectorIdentity Programs.srl srlProgramIdentity := by
  refine {
    exactProgram := rfl
    familyAdmission := by decide
    manifestUnique := by
      rw [exactProductionProgramIdentities]
      decide
    mnemonicUnique := by
      rw [exactProductionProgramIdentities]
      decide
  }

set_option maxRecDepth 30000 in
theorem sra_exactSelectorIdentity :
    ExactSelectorIdentity Programs.sra sraProgramIdentity := by
  refine {
    exactProgram := rfl
    familyAdmission := by decide
    manifestUnique := by
      rw [exactProductionProgramIdentities]
      decide
    mnemonicUnique := by
      rw [exactProductionProgramIdentities]
      decide
  }

set_option maxRecDepth 30000 in
theorem slli_exactSelectorIdentity :
    ExactSelectorIdentity Programs.slli slliProgramIdentity := by
  refine {
    exactProgram := rfl
    familyAdmission := by decide
    manifestUnique := by
      rw [exactProductionProgramIdentities]
      decide
    mnemonicUnique := by
      rw [exactProductionProgramIdentities]
      decide
  }

set_option maxRecDepth 30000 in
theorem srli_exactSelectorIdentity :
    ExactSelectorIdentity Programs.srli srliProgramIdentity := by
  refine {
    exactProgram := rfl
    familyAdmission := by decide
    manifestUnique := by
      rw [exactProductionProgramIdentities]
      decide
    mnemonicUnique := by
      rw [exactProductionProgramIdentities]
      decide
  }

set_option maxRecDepth 30000 in
theorem srai_exactSelectorIdentity :
    ExactSelectorIdentity Programs.srai sraiProgramIdentity := by
  refine {
    exactProgram := rfl
    familyAdmission := by decide
    manifestUnique := by
      rw [exactProductionProgramIdentities]
      decide
    mnemonicUnique := by
      rw [exactProductionProgramIdentities]
      decide
  }

/-!
An exact production program is part of each public premise.  Its accepted
opcode-selector expression pins the row's semantic tag; callers do not supply
that internal tag as a separate assumption.
-/
set_option maxRecDepth 30000 in
private theorem regProgramNodesShared (expected : ShiftKind) :
    (regProgram expected).nodes = Programs.sll.nodes := by
  cases expected <;> rfl

set_option maxRecDepth 30000 in
private theorem immProgramNodesShared (expected : ShiftKind) :
    (immProgram expected).nodes = Programs.slli.nodes := by
  cases expected <;> rfl

private def lookupTupleEntry?
    (index : Nat)
    (lookup : Option EvaluatedLookup) :
    Option M31 :=
  lookup.bind fun evaluated => evaluated.tuple[index]?

private theorem shiftsRegOpcodeIdBound (kind : ShiftKind) :
    shiftsRegOpcodeId kind < M31.modulus := by
  cases kind <;> decide

private theorem shiftsImmOpcodeIdBound (kind : ShiftKind) :
    shiftsImmOpcodeId kind < M31.modulus := by
  cases kind <;> decide

private theorem sllSourceProjection :
    Programs.sll.source = Programs.sllSource := rfl

private theorem srlSourceProjection :
    Programs.srl.source = Programs.srlSource := rfl

private theorem sraSourceProjection :
    Programs.sra.source = Programs.sraSource := rfl

private theorem slliSourceProjection :
    Programs.slli.source = Programs.slliSource := rfl

private theorem srliSourceProjection :
    Programs.srli.source = Programs.srliSource := rfl

private theorem sraiSourceProjection :
    Programs.srai.source = Programs.sraiSource := rfl

set_option maxRecDepth 30000 in
private theorem regSelectorNodeFromProjection
    (row : ShiftsRegRow)
    (witness : RegWitness row) :
    (regEvaluation row witness).nodes.getSymbolic 345 =
      M31.reduce (shiftsRegOpcodeId row.semantic.kind) := by
  have projected :=
    congrArg (lookupTupleEntry? 1)
      (reg_exactRelationProjection row witness).program
  cases kind : row.semantic.kind <;>
    simpa [
      lookupTupleEntry?,
      regEvaluation, regProgram, kind,
      sllSourceProjection, srlSourceProjection, sraSourceProjection,
      Programs.sllSource, Programs.srlSource, Programs.sraSource,
      LocalProgram.evalSymbolic,
      SymbolicEvaluation.lookup?, Event.evalSymbolic,
      EvaluatedEvent.lookup?,
      programRelationLookup, shiftsRegOpcodeId,
    ] using projected

set_option maxRecDepth 30000 in
private theorem immSelectorNodeFromProjection
    (row : ShiftsImmRow)
    (witness : ImmWitness row) :
    (immEvaluation row witness).nodes.getSymbolic 328 =
      M31.reduce (shiftsImmOpcodeId row.semantic.kind) := by
  have projected :=
    congrArg (lookupTupleEntry? 1)
      (imm_exactRelationProjection row witness).program
  cases kind : row.semantic.kind <;>
    simpa [
      lookupTupleEntry?,
      immEvaluation, immProgram, kind,
      slliSourceProjection, srliSourceProjection, sraiSourceProjection,
      Programs.slliSource, Programs.srliSource, Programs.sraiSource,
      LocalProgram.evalSymbolic,
      SymbolicEvaluation.lookup?, Event.evalSymbolic,
      EvaluatedEvent.lookup?,
      immediateProgramRelationLookup, shiftsImmOpcodeId,
    ] using projected

set_option maxRecDepth 30000 in
private theorem regExactSelectorNode
    (expected : ShiftKind)
    (row : ShiftsRegRow)
    (witness : RegWitness row) :
    ((regProgram expected).evalNodesSymbolic
        (regColumns row witness)).getSymbolic 345 =
      M31.reduce (shiftsRegOpcodeId row.semantic.kind) := by
  simpa only [
    regEvaluation,
    LocalProgram.evalSymbolic,
    LocalProgram.evalNodesSymbolic,
    regProgramNodesShared,
  ] using regSelectorNodeFromProjection row witness

set_option maxRecDepth 30000 in
private theorem immExactSelectorNode
    (expected : ShiftKind)
    (row : ShiftsImmRow)
    (witness : ImmWitness row) :
    ((immProgram expected).evalNodesSymbolic
        (immColumns row witness)).getSymbolic 328 =
      M31.reduce (shiftsImmOpcodeId row.semantic.kind) := by
  simpa only [
    immEvaluation,
    LocalProgram.evalSymbolic,
    LocalProgram.evalNodesSymbolic,
    immProgramNodesShared,
  ] using immSelectorNodeFromProjection row witness

set_option maxRecDepth 30000 in
private theorem regAcceptedSelectorNode
    (expected : ShiftKind)
    (row : ShiftsRegRow)
    (witness : RegWitness row)
    (active :
      ((regProgram expected).evalSymbolic
          (regColumns row witness)).activeSelectorsAccepted = true) :
    ((regProgram expected).evalNodesSymbolic
        (regColumns row witness)).getSymbolic 345 =
      M31.reduce (shiftsRegOpcodeId expected) := by
  have selectorsAccepted := active
  simp only [
    SymbolicEvaluation.activeSelectorsAccepted,
    Bool.and_eq_true,
  ] at selectorsAccepted
  have opcodeAccepted := selectorsAccepted.2
  cases expected <;>
    simpa [
      regProgram,
      LocalProgram.evalSymbolic,
      sllSourceProjection, srlSourceProjection, sraSourceProjection,
      Programs.sllSource, Programs.srlSource, Programs.sraSource,
      M31.ofNat?, M31.modulus_eq,
      beq_iff_eq, shiftsRegOpcodeId,
    ] using opcodeAccepted

set_option maxRecDepth 30000 in
private theorem immAcceptedSelectorNode
    (expected : ShiftKind)
    (row : ShiftsImmRow)
    (witness : ImmWitness row)
    (active :
      ((immProgram expected).evalSymbolic
          (immColumns row witness)).activeSelectorsAccepted = true) :
    ((immProgram expected).evalNodesSymbolic
        (immColumns row witness)).getSymbolic 328 =
      M31.reduce (shiftsImmOpcodeId expected) := by
  have selectorsAccepted := active
  simp only [
    SymbolicEvaluation.activeSelectorsAccepted,
    Bool.and_eq_true,
  ] at selectorsAccepted
  have opcodeAccepted := selectorsAccepted.2
  cases expected <;>
    simpa [
      immProgram,
      LocalProgram.evalSymbolic,
      slliSourceProjection, srliSourceProjection, sraiSourceProjection,
      Programs.slliSource, Programs.srliSource, Programs.sraiSource,
      M31.ofNat?, M31.modulus_eq,
      beq_iff_eq, shiftsImmOpcodeId,
    ] using opcodeAccepted

private theorem regKindOfExactActive
    (expected : ShiftKind)
    (row : ShiftsRegRow)
    (witness : RegWitness row)
    (active :
      ((regProgram expected).evalSymbolic
          (regColumns row witness)).activeSelectorsAccepted = true) :
    row.semantic.kind = expected := by
  have ids :
      M31.reduce (shiftsRegOpcodeId row.semantic.kind) =
        M31.reduce (shiftsRegOpcodeId expected) := by
    calc
      _ = ((regProgram expected).evalNodesSymbolic
            (regColumns row witness)).getSymbolic 345 :=
        (regExactSelectorNode expected row witness).symm
      _ = _ := regAcceptedSelectorNode expected row witness active
  have opcodeIds :
      shiftsRegOpcodeId row.semantic.kind =
        shiftsRegOpcodeId expected :=
    (M31.reduce_injective_of_lt
      (shiftsRegOpcodeIdBound row.semantic.kind)
      (shiftsRegOpcodeIdBound expected)).mp ids
  cases expected <;>
    cases actual : row.semantic.kind <;>
    simp_all [shiftsRegOpcodeId]

private theorem immKindOfExactActive
    (expected : ShiftKind)
    (row : ShiftsImmRow)
    (witness : ImmWitness row)
    (active :
      ((immProgram expected).evalSymbolic
          (immColumns row witness)).activeSelectorsAccepted = true) :
    row.semantic.kind = expected := by
  have ids :
      M31.reduce (shiftsImmOpcodeId row.semantic.kind) =
        M31.reduce (shiftsImmOpcodeId expected) := by
    calc
      _ = ((immProgram expected).evalNodesSymbolic
            (immColumns row witness)).getSymbolic 328 :=
        (immExactSelectorNode expected row witness).symm
      _ = _ := immAcceptedSelectorNode expected row witness active
  have opcodeIds :
      shiftsImmOpcodeId row.semantic.kind =
        shiftsImmOpcodeId expected :=
    (M31.reduce_injective_of_lt
      (shiftsImmOpcodeIdBound row.semantic.kind)
      (shiftsImmOpcodeIdBound expected)).mp ids
  cases expected <;>
    cases actual : row.semantic.kind <;>
    simp_all [shiftsImmOpcodeId]

structure ImmPublicationResult
    (program : LocalProgram)
    (expected : ProgramIdentity)
    (row : ShiftsImmRow)
    (witness : ImmWitness row)
    (environment : ShiftsImmEnvironment row)
    (relationHolds : EvaluatedLookup → Prop) : Prop where
  selectedProgram : immProgram row.semantic.kind = program
  selectorIdentity : ExactSelectorIdentity program expected
  activeProductionRow :
    (immEvaluation row witness).activeSelectorsAccepted = true
  holds : ShiftsImmHolds row
  semantic : ShiftsImmRefinement row environment
  exactOrderedTuples : ImmExactRelationProjection row witness
  everyLiveNonFixedRelation :
    ∀ lookup, lookup ∈ (immEvaluation row witness).liveLookups →
      lookup.tableId = none → relationHolds lookup

structure RegPublicationResult
    (program : LocalProgram)
    (expected : ProgramIdentity)
    (row : ShiftsRegRow)
    (witness : RegWitness row)
    (environment : ShiftsRegEnvironment row)
    (relationHolds : EvaluatedLookup → Prop) : Prop where
  selectedProgram : regProgram row.semantic.kind = program
  selectorIdentity : ExactSelectorIdentity program expected
  activeProductionRow :
    (regEvaluation row witness).activeSelectorsAccepted = true
  holds : ShiftsRegHolds row
  semantic : ShiftsRegRefinement row environment
  exactOrderedTuples : RegExactRelationProjection row witness
  everyLiveNonFixedRelation :
    ∀ lookup, lookup ∈ (regEvaluation row witness).liveLookups →
      lookup.tableId = none → relationHolds lookup

/-
Publication implication for the exact generated SLL evaluator.  Its premises
are only production acceptance, profile admission, and explicit
program/register/projection bindings; `ShiftsRegHolds` is derived.
-/
set_option maxRecDepth 30000 in
theorem sll_accepted_air_implies_retirement
    (row : ShiftsRegRow)
    (witness : RegWitness row)
    (relationHolds : EvaluatedLookup → Prop)
    (environment : ShiftsRegEnvironment row)
    (admission : RegAdmission row)
    (bindings : RegBindings row witness)
    (accepted :
      AcceptedProductionEvaluation
        (Programs.sll.evalSymbolic (regColumns row witness))
        relationHolds) :
    RegPublicationResult Programs.sll sllProgramIdentity
        row witness environment relationHolds ∧
      Decode.isSll environment.word = true ∧
      shiftsRegRetirement row =
        executeSll environment.pre.pc
          (environment.pre.registers row.rs1)
          (environment.pre.registers row.rs2) row.semantic.rd := by
  have selector : row.semantic.kind = .sll :=
    regKindOfExactActive .sll row witness accepted.activeProductionRow
  have acceptedRow : RegAcceptance row witness relationHolds := by
    simpa only [RegAcceptance, regEvaluation, selector, regProgram]
      using accepted
  have holds :=
    regHoldsOfAccepted
      row witness relationHolds admission bindings acceptedRow
  have opcode :=
    sll_refines row environment holds selector
  exact ⟨{
    selectedProgram := by simp [regProgram, selector]
    selectorIdentity := sll_exactSelectorIdentity
    activeProductionRow := acceptedRow.activeProductionRow
    holds
    semantic := opcode.1
    exactOrderedTuples := reg_exactRelationProjection row witness
    everyLiveNonFixedRelation := acceptedRow.liveRelations
  }, opcode.2⟩

set_option maxRecDepth 30000 in
theorem srl_accepted_air_implies_retirement
    (row : ShiftsRegRow)
    (witness : RegWitness row)
    (relationHolds : EvaluatedLookup → Prop)
    (environment : ShiftsRegEnvironment row)
    (admission : RegAdmission row)
    (bindings : RegBindings row witness)
    (accepted :
      AcceptedProductionEvaluation
        (Programs.srl.evalSymbolic (regColumns row witness))
        relationHolds) :
    RegPublicationResult Programs.srl srlProgramIdentity
        row witness environment relationHolds ∧
      Decode.isSrl environment.word = true ∧
      shiftsRegRetirement row =
        executeSrl environment.pre.pc
          (environment.pre.registers row.rs1)
          (environment.pre.registers row.rs2) row.semantic.rd ∧
      row.semantic.rs1Sign = false := by
  have selector : row.semantic.kind = .srl :=
    regKindOfExactActive .srl row witness accepted.activeProductionRow
  have acceptedRow : RegAcceptance row witness relationHolds := by
    simpa only [RegAcceptance, regEvaluation, selector, regProgram]
      using accepted
  have holds :=
    regHoldsOfAccepted
      row witness relationHolds admission bindings acceptedRow
  have opcode :=
    srl_refines row environment holds selector
  exact ⟨{
    selectedProgram := by simp [regProgram, selector]
    selectorIdentity := srl_exactSelectorIdentity
    activeProductionRow := acceptedRow.activeProductionRow
    holds
    semantic := opcode.1
    exactOrderedTuples := reg_exactRelationProjection row witness
    everyLiveNonFixedRelation := acceptedRow.liveRelations
  }, opcode.2⟩

set_option maxRecDepth 30000 in
theorem sra_accepted_air_implies_retirement
    (row : ShiftsRegRow)
    (witness : RegWitness row)
    (relationHolds : EvaluatedLookup → Prop)
    (environment : ShiftsRegEnvironment row)
    (admission : RegAdmission row)
    (bindings : RegBindings row witness)
    (accepted :
      AcceptedProductionEvaluation
        (Programs.sra.evalSymbolic (regColumns row witness))
        relationHolds) :
    RegPublicationResult Programs.sra sraProgramIdentity
        row witness environment relationHolds ∧
      Decode.isSra environment.word = true ∧
      shiftsRegRetirement row =
        executeSra environment.pre.pc
          (environment.pre.registers row.rs1)
          (environment.pre.registers row.rs2) row.semantic.rd ∧
      row.semantic.rs1Sign =
        (environment.pre.registers row.rs1).msb := by
  have selector : row.semantic.kind = .sra :=
    regKindOfExactActive .sra row witness accepted.activeProductionRow
  have acceptedRow : RegAcceptance row witness relationHolds := by
    simpa only [RegAcceptance, regEvaluation, selector, regProgram]
      using accepted
  have holds :=
    regHoldsOfAccepted
      row witness relationHolds admission bindings acceptedRow
  have opcode :=
    sra_refines row environment holds selector
  exact ⟨{
    selectedProgram := by simp [regProgram, selector]
    selectorIdentity := sra_exactSelectorIdentity
    activeProductionRow := acceptedRow.activeProductionRow
    holds
    semantic := opcode.1
    exactOrderedTuples := reg_exactRelationProjection row witness
    everyLiveNonFixedRelation := acceptedRow.liveRelations
  }, opcode.2⟩

set_option maxRecDepth 30000 in
theorem slli_accepted_air_implies_retirement
    (row : ShiftsImmRow)
    (witness : ImmWitness row)
    (relationHolds : EvaluatedLookup → Prop)
    (environment : ShiftsImmEnvironment row)
    (admission : ImmAdmission row)
    (bindings : ImmBindings row witness)
    (accepted :
      AcceptedProductionEvaluation
        (Programs.slli.evalSymbolic (immColumns row witness))
        relationHolds) :
    ImmPublicationResult Programs.slli slliProgramIdentity
        row witness environment relationHolds ∧
      Decode.isSlli environment.word = true ∧
      shiftsImmRetirement row =
        executeSlli environment.pre.pc
          (environment.pre.registers row.rs1)
          row.semantic.rd (shiftsImmShamt row) := by
  have selector : row.semantic.kind = .sll :=
    immKindOfExactActive .sll row witness accepted.activeProductionRow
  have acceptedRow : ImmAcceptance row witness relationHolds := by
    simpa only [ImmAcceptance, immEvaluation, selector, immProgram]
      using accepted
  have holds :=
    immHoldsOfAccepted
      row witness relationHolds admission bindings acceptedRow
  have opcode :=
    slli_refines row environment holds selector
  exact ⟨{
    selectedProgram := by simp [immProgram, selector]
    selectorIdentity := slli_exactSelectorIdentity
    activeProductionRow := acceptedRow.activeProductionRow
    holds
    semantic := opcode.1
    exactOrderedTuples := imm_exactRelationProjection row witness
    everyLiveNonFixedRelation := acceptedRow.liveRelations
  }, opcode.2⟩

set_option maxRecDepth 30000 in
theorem srli_accepted_air_implies_retirement
    (row : ShiftsImmRow)
    (witness : ImmWitness row)
    (relationHolds : EvaluatedLookup → Prop)
    (environment : ShiftsImmEnvironment row)
    (admission : ImmAdmission row)
    (bindings : ImmBindings row witness)
    (accepted :
      AcceptedProductionEvaluation
        (Programs.srli.evalSymbolic (immColumns row witness))
        relationHolds) :
    ImmPublicationResult Programs.srli srliProgramIdentity
        row witness environment relationHolds ∧
      Decode.isSrli environment.word = true ∧
      shiftsImmRetirement row =
        executeSrli environment.pre.pc
          (environment.pre.registers row.rs1)
          row.semantic.rd (shiftsImmShamt row) ∧
      row.semantic.rs1Sign = false := by
  have selector : row.semantic.kind = .srl :=
    immKindOfExactActive .srl row witness accepted.activeProductionRow
  have acceptedRow : ImmAcceptance row witness relationHolds := by
    simpa only [ImmAcceptance, immEvaluation, selector, immProgram]
      using accepted
  have holds :=
    immHoldsOfAccepted
      row witness relationHolds admission bindings acceptedRow
  have opcode :=
    srli_refines row environment holds selector
  exact ⟨{
    selectedProgram := by simp [immProgram, selector]
    selectorIdentity := srli_exactSelectorIdentity
    activeProductionRow := acceptedRow.activeProductionRow
    holds
    semantic := opcode.1
    exactOrderedTuples := imm_exactRelationProjection row witness
    everyLiveNonFixedRelation := acceptedRow.liveRelations
  }, opcode.2⟩

set_option maxRecDepth 30000 in
theorem srai_accepted_air_implies_retirement
    (row : ShiftsImmRow)
    (witness : ImmWitness row)
    (relationHolds : EvaluatedLookup → Prop)
    (environment : ShiftsImmEnvironment row)
    (admission : ImmAdmission row)
    (bindings : ImmBindings row witness)
    (accepted :
      AcceptedProductionEvaluation
        (Programs.srai.evalSymbolic (immColumns row witness))
        relationHolds) :
    ImmPublicationResult Programs.srai sraiProgramIdentity
        row witness environment relationHolds ∧
      Decode.isSrai environment.word = true ∧
      shiftsImmRetirement row =
        executeSrai environment.pre.pc
          (environment.pre.registers row.rs1)
          row.semantic.rd (shiftsImmShamt row) ∧
      row.semantic.rs1Sign =
        (environment.pre.registers row.rs1).msb := by
  have selector : row.semantic.kind = .sra :=
    immKindOfExactActive .sra row witness accepted.activeProductionRow
  have acceptedRow : ImmAcceptance row witness relationHolds := by
    simpa only [ImmAcceptance, immEvaluation, selector, immProgram]
      using accepted
  have holds :=
    immHoldsOfAccepted
      row witness relationHolds admission bindings acceptedRow
  have opcode :=
    srai_refines row environment holds selector
  exact ⟨{
    selectedProgram := by simp [immProgram, selector]
    selectorIdentity := srai_exactSelectorIdentity
    activeProductionRow := acceptedRow.activeProductionRow
    holds
    semantic := opcode.1
    exactOrderedTuples := imm_exactRelationProjection row witness
    everyLiveNonFixedRelation := acceptedRow.liveRelations
  }, opcode.2⟩

end RiscvRefinement.Publication.TeamB.Shifts
