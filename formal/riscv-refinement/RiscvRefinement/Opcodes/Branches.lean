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

/-! The production-facing theorem uses independent raw AIR columns. -/

abbrev RawRow := Air.Bridge.Branches.Eq.RawRow
abbrev RawWitness := Air.Bridge.Branches.Eq.RawWitness
abbrev RawAcceptance := Air.Bridge.Branches.Eq.RawAcceptance
abbrev RawAdmission := Air.Bridge.Branches.Eq.RawAdmission

def rawWord (row : RawRow) : InstructionWord :=
  Decode.encodeBranch row.kind.decode row.immediateEncoded row.rs2 row.rs1

def rawExpectedTaken (row : RawRow) : Bool :=
  match row.kind with
  | .beq => decide (row.rs1Next.word = row.rs2Next.word)
  | .bne => decide (row.rs1Next.word ≠ row.rs2Next.word)

theorem rawTakenIsArchitectural (row : RawRow) :
    Air.Bridge.Branches.Eq.rawTaken row = rawExpectedTaken row := by
  cases row.kind <;>
    simp [
      Air.Bridge.Branches.Eq.rawTaken,
      Air.Bridge.Branches.Eq.rawEqual,
      rawExpectedTaken,
    ] <;>
    rfl

/--
`BEQ` and `BNE` are exact Boolean complements on the same pair of source
words.  This is stated independently of any witness so it is part of the
architectural contract, rather than merely a property of the examples.
-/
theorem beq_bne_complement_theorem (left right : WordBytes) :
    (decide (left.word = right.word) : Bool) =
      !(decide (left.word ≠ right.word) : Bool) := by
  by_cases equal : left.word = right.word <;> simp [equal]

structure RawRefinement
    (row : RawRow) (witness : RawWitness row) : Prop where
  production :
    Air.Bridge.Branches.Eq.RawProductionRefinement row witness
  decode :
    Decode.isBranch row.kind.decode (rawWord row) = true ∧
      Decode.decodeBImmediate (rawWord row) =
        Decode.branchImmediate row.immediateEncoded ∧
      Decode.decodeRs2 (rawWord row) = row.rs2 ∧
      Decode.decodeRs1 (rawWord row) = row.rs1
  sourcesReadOnly :
    row.rs1Next = row.rs1Previous ∧ row.rs2Next = row.rs2Previous
  decision :
    row.branchTaken = rawExpectedTaken row
  retirementPc :
    (Air.Bridge.Branches.Eq.rawStateEmitLookup row).tuple[0]? =
      some (Air.Bridge.Branches.bitVecM31
        (Air.Bridge.Branches.selectedPc
          row.pc row.immediateEncoded (rawExpectedTaken row)))
  exactProgramTuple :
    (Air.Bridge.Branches.Eq.rawProgramLookup row).tuple = #[
      Air.Bridge.Branches.bitVecM31 row.pc,
      M31.reduce row.kind.manifestId,
      Air.Bridge.Branches.bitVecM31 row.rs1,
      Air.Bridge.Branches.bitVecM31 row.rs2,
      Air.Bridge.Branches.immediateField row.immediateEncoded
    ]
  targetNoWrap :
    if (Air.Bridge.Branches.immediate row.immediateEncoded).msb
    then
      2 ^ 13 -
          (Air.Bridge.Branches.immediate row.immediateEncoded).toNat ≤
        row.pc.toNat
    else
      row.pc.toNat +
          (Air.Bridge.Branches.immediate row.immediateEncoded).toNat <
        M31.modulus
  targetAligned :
    (Air.Bridge.Branches.immediate row.immediateEncoded).toNat % 4 = 0
  noRegisterOrMemoryEffect :
    Retirement.write
        { nextPc :=
            Air.Bridge.Branches.selectedPc
              row.pc row.immediateEncoded (rawExpectedTaken row)
          write := none } = none ∧
      Retirement.read
        { nextPc :=
            Air.Bridge.Branches.selectedPc
              row.pc row.immediateEncoded (rawExpectedTaken row)
          write := none } = none ∧
      Retirement.store
        { nextPc :=
            Air.Bridge.Branches.selectedPc
              row.pc row.immediateEncoded (rawExpectedTaken row)
          write := none } = none

theorem rawRefines
    (row : RawRow)
    (witness : RawWitness row)
    (admission : RawAdmission row)
    (accepted : RawAcceptance row witness) :
    RawRefinement row witness := by
  have production :=
    Air.Bridge.Branches.Eq.rawSound row witness admission accepted
  refine {
    production := production
    decode :=
      Decode.encode_branch_is_canonical
        row.kind.decode row.immediateEncoded row.rs2 row.rs1
    sourcesReadOnly := production.sourceReadOnly
    decision := production.decision.trans (rawTakenIsArchitectural row)
    retirementPc := ?_
    exactProgramTuple := ?_
    targetNoWrap := admission.control.targetNoWrap
    targetAligned := admission.control.targetAligned
    noRegisterOrMemoryEffect := by simp
  }
  · simpa [rawTakenIsArchitectural row] using production.nextPc
  · simp [
      Air.Bridge.Branches.Eq.rawProgramLookup,
      admission.immediateFieldBinds,
    ]

theorem beq_selector_theorem
    (row : RawRow)
    (witness : RawWitness row)
    (_selector : row.kind = .beq) :
    (Air.Bridge.Branches.Eq.rawEvaluation row witness).activeSelectorsAccepted =
      true :=
  Air.Bridge.Branches.Eq.rawSelectorAccepted row witness

theorem bne_selector_theorem
    (row : RawRow)
    (witness : RawWitness row)
    (_selector : row.kind = .bne) :
    (Air.Bridge.Branches.Eq.rawEvaluation row witness).activeSelectorsAccepted =
      true :=
  Air.Bridge.Branches.Eq.rawSelectorAccepted row witness

theorem beq_refinement_theorem
    (row : RawRow)
    (witness : RawWitness row)
    (_selector : row.kind = .beq)
    (admission : RawAdmission row)
    (accepted : RawAcceptance row witness) :
    RawRefinement row witness :=
  rawRefines row witness admission accepted

theorem bne_refinement_theorem
    (row : RawRow)
    (witness : RawWitness row)
    (_selector : row.kind = .bne)
    (admission : RawAdmission row)
    (accepted : RawAcceptance row witness) :
    RawRefinement row witness :=
  rawRefines row witness admission accepted

theorem beq_tuple_theorem
    (row : RawRow)
    (selector : row.kind = .beq)
    (admission : RawAdmission row) :
    (Air.Bridge.Branches.Eq.rawProgramLookup row).tuple = #[
      Air.Bridge.Branches.bitVecM31 row.pc,
      M31.reduce 27,
      Air.Bridge.Branches.bitVecM31 row.rs1,
      Air.Bridge.Branches.bitVecM31 row.rs2,
      Air.Bridge.Branches.immediateField row.immediateEncoded
    ] := by
  simp [
    Air.Bridge.Branches.Eq.rawProgramLookup,
    selector,
    Air.Bridge.Branches.Eq.Kind.manifestId,
    admission.immediateFieldBinds,
  ]

theorem bne_tuple_theorem
    (row : RawRow)
    (selector : row.kind = .bne)
    (admission : RawAdmission row) :
    (Air.Bridge.Branches.Eq.rawProgramLookup row).tuple = #[
      Air.Bridge.Branches.bitVecM31 row.pc,
      M31.reduce 28,
      Air.Bridge.Branches.bitVecM31 row.rs1,
      Air.Bridge.Branches.bitVecM31 row.rs2,
      Air.Bridge.Branches.immediateField row.immediateEncoded
    ] := by
  simp [
    Air.Bridge.Branches.Eq.rawProgramLookup,
    selector,
    Air.Bridge.Branches.Eq.Kind.manifestId,
    admission.immediateFieldBinds,
  ]

private theorem selectorTakenAndFallthroughRefine
    (kind : Air.Bridge.Branches.Eq.Kind) :
    (∃ row witness,
      row.kind = kind ∧ Admission row ∧ Acceptance row witness ∧
        Refinement row witness ∧ expectedTaken row = true) ∧
    (∃ row witness,
      row.kind = kind ∧ Admission row ∧ Acceptance row witness ∧
        Refinement row witness ∧ expectedTaken row = false) := by
  constructor
  · refine ⟨Air.Bridge.Branches.Eq.exampleRow kind true,
      Air.Bridge.Branches.Eq.exampleWitness kind true, rfl,
      Air.Bridge.Branches.Eq.exampleAdmission kind true,
      Air.Bridge.Branches.Eq.exampleAcceptance kind true,
      refines _ _
        (Air.Bridge.Branches.Eq.exampleAdmission kind true)
        (Air.Bridge.Branches.Eq.exampleAcceptance kind true), ?_⟩
    rw [← decisionIsArchitectural]
    exact Air.Bridge.Branches.Eq.exampleTaken kind true
  · refine ⟨Air.Bridge.Branches.Eq.exampleRow kind false,
      Air.Bridge.Branches.Eq.exampleWitness kind false, rfl,
      Air.Bridge.Branches.Eq.exampleAdmission kind false,
      Air.Bridge.Branches.Eq.exampleAcceptance kind false,
      refines _ _
        (Air.Bridge.Branches.Eq.exampleAdmission kind false)
        (Air.Bridge.Branches.Eq.exampleAcceptance kind false), ?_⟩
    rw [← decisionIsArchitectural]
    exact Air.Bridge.Branches.Eq.exampleTaken kind false

theorem beq_nonvacuity_theorem :
    (∃ row witness,
      row.kind = Air.Bridge.Branches.Eq.Kind.beq ∧
        Admission row ∧ Acceptance row witness ∧
        Refinement row witness ∧ expectedTaken row = true) ∧
    (∃ row witness,
      row.kind = Air.Bridge.Branches.Eq.Kind.beq ∧
        Admission row ∧ Acceptance row witness ∧
        Refinement row witness ∧ expectedTaken row = false) :=
  selectorTakenAndFallthroughRefine .beq

theorem bne_nonvacuity_theorem :
    (∃ row witness,
      row.kind = Air.Bridge.Branches.Eq.Kind.bne ∧
        Admission row ∧ Acceptance row witness ∧
        Refinement row witness ∧ expectedTaken row = true) ∧
    (∃ row witness,
      row.kind = Air.Bridge.Branches.Eq.Kind.bne ∧
        Admission row ∧ Acceptance row witness ∧
        Refinement row witness ∧ expectedTaken row = false) :=
  selectorTakenAndFallthroughRefine .bne

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

abbrev RawRow := Air.Bridge.Branches.Lt.RawRow
abbrev RawWitness := Air.Bridge.Branches.Lt.RawWitness
abbrev RawAcceptance := Air.Bridge.Branches.Lt.RawAcceptance
abbrev RawAdmission := Air.Bridge.Branches.Lt.RawAdmission

def rawWord (row : RawRow) : InstructionWord :=
  Decode.encodeBranch row.kind.decode row.immediateEncoded row.rs2 row.rs1

def rawExpectedLess (row : RawRow) : Bool :=
  if row.kind.signed
  then
    Air.Bridge.Branches.Lt.signedLess
      row.rs1Next.word row.rs2Next.word
  else decide (row.rs1Next.word.toNat < row.rs2Next.word.toNat)

def rawExpectedTaken (row : RawRow) : Bool :=
  if row.kind.lessOpcode
  then rawExpectedLess row
  else !rawExpectedLess row

theorem rawComparisonIsArchitectural (row : RawRow) :
    Air.Bridge.Branches.Lt.rawLess row = rawExpectedLess row := by
  exact Air.Bridge.Branches.Lt.rawLessEqArchitectural row

theorem rawDecisionIsArchitectural (row : RawRow) :
    Air.Bridge.Branches.Lt.rawTaken row = rawExpectedTaken row := by
  simp [
    Air.Bridge.Branches.Lt.rawTaken,
    rawExpectedTaken,
    rawExpectedLess,
    Air.Bridge.Branches.Lt.rawLessEqArchitectural,
  ]

structure RawRefinement
    (row : RawRow) (witness : RawWitness row) : Prop where
  production :
    Air.Bridge.Branches.Lt.RawProductionRefinement row witness
  decode :
    Decode.isBranch row.kind.decode (rawWord row) = true ∧
      Decode.decodeBImmediate (rawWord row) =
        Decode.branchImmediate row.immediateEncoded ∧
      Decode.decodeRs2 (rawWord row) = row.rs2 ∧
      Decode.decodeRs1 (rawWord row) = row.rs1
  sourcesReadOnly :
    row.rs1Next = row.rs1Previous ∧ row.rs2Next = row.rs2Previous
  comparison :
    row.comparisonLess = rawExpectedLess row
  decision :
    row.branchTaken = rawExpectedTaken row
  retirementPc :
    (Air.Bridge.Branches.Lt.rawStateEmitLookup row).tuple[0]? =
      some (Air.Bridge.Branches.bitVecM31
        (Air.Bridge.Branches.selectedPc
          row.pc row.immediateEncoded (rawExpectedTaken row)))
  exactProgramTuple :
    (Air.Bridge.Branches.Lt.rawProgramLookup row).tuple = #[
      Air.Bridge.Branches.bitVecM31 row.pc,
      M31.reduce row.kind.manifestId,
      Air.Bridge.Branches.bitVecM31 row.rs1,
      Air.Bridge.Branches.bitVecM31 row.rs2,
      Air.Bridge.Branches.immediateField row.immediateEncoded
    ]
  targetNoWrap :
    if (Air.Bridge.Branches.immediate row.immediateEncoded).msb
    then
      2 ^ 13 -
          (Air.Bridge.Branches.immediate row.immediateEncoded).toNat ≤
        row.pc.toNat
    else
      row.pc.toNat +
          (Air.Bridge.Branches.immediate row.immediateEncoded).toNat <
        M31.modulus
  targetAligned :
    (Air.Bridge.Branches.immediate row.immediateEncoded).toNat % 4 = 0
  noRegisterOrMemoryEffect :
    Retirement.write
        { nextPc :=
            Air.Bridge.Branches.selectedPc
              row.pc row.immediateEncoded (rawExpectedTaken row)
          write := none } = none ∧
      Retirement.read
        { nextPc :=
            Air.Bridge.Branches.selectedPc
              row.pc row.immediateEncoded (rawExpectedTaken row)
          write := none } = none ∧
      Retirement.store
        { nextPc :=
            Air.Bridge.Branches.selectedPc
              row.pc row.immediateEncoded (rawExpectedTaken row)
          write := none } = none

theorem rawRefines
    (row : RawRow)
    (witness : RawWitness row)
    (admission : RawAdmission row)
    (accepted : RawAcceptance row witness) :
    RawRefinement row witness := by
  have production :=
    Air.Bridge.Branches.Lt.rawSound row witness admission accepted
  refine {
    production := production
    decode :=
      Decode.encode_branch_is_canonical
        row.kind.decode row.immediateEncoded row.rs2 row.rs1
    sourcesReadOnly := production.sourceReadOnly
    comparison :=
      production.comparison.trans (rawComparisonIsArchitectural row)
    decision :=
      production.decision.trans (rawDecisionIsArchitectural row)
    retirementPc := ?_
    exactProgramTuple := ?_
    targetNoWrap := admission.control.targetNoWrap
    targetAligned := admission.control.targetAligned
    noRegisterOrMemoryEffect := by simp
  }
  · simpa [rawDecisionIsArchitectural row] using production.nextPc
  · simp [
      Air.Bridge.Branches.Lt.rawProgramLookup,
      admission.immediateFieldBinds,
    ]

theorem blt_selector_theorem
    (row : RawRow)
    (witness : RawWitness row)
    (_selector : row.kind = .blt) :
    (Air.Bridge.Branches.Lt.rawEvaluation row witness).activeSelectorsAccepted =
      true :=
  Air.Bridge.Branches.Lt.rawSelectorAccepted row witness

theorem bge_selector_theorem
    (row : RawRow)
    (witness : RawWitness row)
    (_selector : row.kind = .bge) :
    (Air.Bridge.Branches.Lt.rawEvaluation row witness).activeSelectorsAccepted =
      true :=
  Air.Bridge.Branches.Lt.rawSelectorAccepted row witness

theorem bltu_selector_theorem
    (row : RawRow)
    (witness : RawWitness row)
    (_selector : row.kind = .bltu) :
    (Air.Bridge.Branches.Lt.rawEvaluation row witness).activeSelectorsAccepted =
      true :=
  Air.Bridge.Branches.Lt.rawSelectorAccepted row witness

theorem bgeu_selector_theorem
    (row : RawRow)
    (witness : RawWitness row)
    (_selector : row.kind = .bgeu) :
    (Air.Bridge.Branches.Lt.rawEvaluation row witness).activeSelectorsAccepted =
      true :=
  Air.Bridge.Branches.Lt.rawSelectorAccepted row witness

theorem blt_refinement_theorem
    (row : RawRow)
    (witness : RawWitness row)
    (_selector : row.kind = .blt)
    (admission : RawAdmission row)
    (accepted : RawAcceptance row witness) :
    RawRefinement row witness :=
  rawRefines row witness admission accepted

theorem bge_refinement_theorem
    (row : RawRow)
    (witness : RawWitness row)
    (_selector : row.kind = .bge)
    (admission : RawAdmission row)
    (accepted : RawAcceptance row witness) :
    RawRefinement row witness :=
  rawRefines row witness admission accepted

theorem bltu_refinement_theorem
    (row : RawRow)
    (witness : RawWitness row)
    (_selector : row.kind = .bltu)
    (admission : RawAdmission row)
    (accepted : RawAcceptance row witness) :
    RawRefinement row witness :=
  rawRefines row witness admission accepted

theorem bgeu_refinement_theorem
    (row : RawRow)
    (witness : RawWitness row)
    (_selector : row.kind = .bgeu)
    (admission : RawAdmission row)
    (accepted : RawAcceptance row witness) :
    RawRefinement row witness :=
  rawRefines row witness admission accepted

theorem blt_tuple_theorem
    (row : RawRow)
    (selector : row.kind = .blt)
    (admission : RawAdmission row) :
    (Air.Bridge.Branches.Lt.rawProgramLookup row).tuple = #[
      Air.Bridge.Branches.bitVecM31 row.pc,
      M31.reduce 29,
      Air.Bridge.Branches.bitVecM31 row.rs1,
      Air.Bridge.Branches.bitVecM31 row.rs2,
      Air.Bridge.Branches.immediateField row.immediateEncoded
    ] := by
  simp [
    Air.Bridge.Branches.Lt.rawProgramLookup,
    selector,
    Air.Bridge.Branches.Lt.Kind.manifestId,
    admission.immediateFieldBinds,
  ]

theorem bge_tuple_theorem
    (row : RawRow)
    (selector : row.kind = .bge)
    (admission : RawAdmission row) :
    (Air.Bridge.Branches.Lt.rawProgramLookup row).tuple = #[
      Air.Bridge.Branches.bitVecM31 row.pc,
      M31.reduce 30,
      Air.Bridge.Branches.bitVecM31 row.rs1,
      Air.Bridge.Branches.bitVecM31 row.rs2,
      Air.Bridge.Branches.immediateField row.immediateEncoded
    ] := by
  simp [
    Air.Bridge.Branches.Lt.rawProgramLookup,
    selector,
    Air.Bridge.Branches.Lt.Kind.manifestId,
    admission.immediateFieldBinds,
  ]

theorem bltu_tuple_theorem
    (row : RawRow)
    (selector : row.kind = .bltu)
    (admission : RawAdmission row) :
    (Air.Bridge.Branches.Lt.rawProgramLookup row).tuple = #[
      Air.Bridge.Branches.bitVecM31 row.pc,
      M31.reduce 31,
      Air.Bridge.Branches.bitVecM31 row.rs1,
      Air.Bridge.Branches.bitVecM31 row.rs2,
      Air.Bridge.Branches.immediateField row.immediateEncoded
    ] := by
  simp [
    Air.Bridge.Branches.Lt.rawProgramLookup,
    selector,
    Air.Bridge.Branches.Lt.Kind.manifestId,
    admission.immediateFieldBinds,
  ]

theorem bgeu_tuple_theorem
    (row : RawRow)
    (selector : row.kind = .bgeu)
    (admission : RawAdmission row) :
    (Air.Bridge.Branches.Lt.rawProgramLookup row).tuple = #[
      Air.Bridge.Branches.bitVecM31 row.pc,
      M31.reduce 32,
      Air.Bridge.Branches.bitVecM31 row.rs1,
      Air.Bridge.Branches.bitVecM31 row.rs2,
      Air.Bridge.Branches.immediateField row.immediateEncoded
    ] := by
  simp [
    Air.Bridge.Branches.Lt.rawProgramLookup,
    selector,
    Air.Bridge.Branches.Lt.Kind.manifestId,
    admission.immediateFieldBinds,
  ]

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

private theorem selectorTakenAndFallthroughRefine
    (kind : Air.Bridge.Branches.Lt.Kind) :
    (∃ row witness,
      row.kind = kind ∧ Admission row ∧ Acceptance row witness ∧
        Refinement row witness ∧ expectedTaken row = true) ∧
    (∃ row witness,
      row.kind = kind ∧ Admission row ∧ Acceptance row witness ∧
        Refinement row witness ∧ expectedTaken row = false) := by
  constructor
  · refine ⟨Air.Bridge.Branches.Lt.exampleRow kind true,
      Air.Bridge.Branches.Lt.exampleWitness kind true, rfl,
      Air.Bridge.Branches.Lt.exampleAdmission kind true,
      Air.Bridge.Branches.Lt.exampleAcceptance kind true,
      refines _ _
        (Air.Bridge.Branches.Lt.exampleAdmission kind true)
        (Air.Bridge.Branches.Lt.exampleAcceptance kind true), ?_⟩
    exact Air.Bridge.Branches.Lt.exampleTaken kind true
  · refine ⟨Air.Bridge.Branches.Lt.exampleRow kind false,
      Air.Bridge.Branches.Lt.exampleWitness kind false, rfl,
      Air.Bridge.Branches.Lt.exampleAdmission kind false,
      Air.Bridge.Branches.Lt.exampleAcceptance kind false,
      refines _ _
        (Air.Bridge.Branches.Lt.exampleAdmission kind false)
        (Air.Bridge.Branches.Lt.exampleAcceptance kind false), ?_⟩
    exact Air.Bridge.Branches.Lt.exampleTaken kind false

theorem blt_nonvacuity_theorem :
    (∃ row witness,
      row.kind = Air.Bridge.Branches.Lt.Kind.blt ∧
        Admission row ∧ Acceptance row witness ∧
        Refinement row witness ∧ expectedTaken row = true) ∧
    (∃ row witness,
      row.kind = Air.Bridge.Branches.Lt.Kind.blt ∧
        Admission row ∧ Acceptance row witness ∧
        Refinement row witness ∧ expectedTaken row = false) :=
  selectorTakenAndFallthroughRefine .blt

theorem bge_nonvacuity_theorem :
    (∃ row witness,
      row.kind = Air.Bridge.Branches.Lt.Kind.bge ∧
        Admission row ∧ Acceptance row witness ∧
        Refinement row witness ∧ expectedTaken row = true) ∧
    (∃ row witness,
      row.kind = Air.Bridge.Branches.Lt.Kind.bge ∧
        Admission row ∧ Acceptance row witness ∧
        Refinement row witness ∧ expectedTaken row = false) :=
  selectorTakenAndFallthroughRefine .bge

theorem bltu_nonvacuity_theorem :
    (∃ row witness,
      row.kind = Air.Bridge.Branches.Lt.Kind.bltu ∧
        Admission row ∧ Acceptance row witness ∧
        Refinement row witness ∧ expectedTaken row = true) ∧
    (∃ row witness,
      row.kind = Air.Bridge.Branches.Lt.Kind.bltu ∧
        Admission row ∧ Acceptance row witness ∧
        Refinement row witness ∧ expectedTaken row = false) :=
  selectorTakenAndFallthroughRefine .bltu

theorem bgeu_nonvacuity_theorem :
    (∃ row witness,
      row.kind = Air.Bridge.Branches.Lt.Kind.bgeu ∧
        Admission row ∧ Acceptance row witness ∧
        Refinement row witness ∧ expectedTaken row = true) ∧
    (∃ row witness,
      row.kind = Air.Bridge.Branches.Lt.Kind.bgeu ∧
        Admission row ∧ Acceptance row witness ∧
        Refinement row witness ∧ expectedTaken row = false) :=
  selectorTakenAndFallthroughRefine .bgeu

private def highBitOperand : WordBytes :=
  { WordBytes.zero with limb3 := BitVec.ofNat 8 128 }

/--
The selector map itself distinguishes signed BLT/BGE from unsigned
BLTU/BGEU, and the architectural ordering distinguishes the canonical
high-bit operand (`0x80000000`) from zero in exactly the signed direction.
-/
theorem ordered_signedness_theorem :
    Air.Bridge.Branches.Lt.Kind.signed .blt = true ∧
      Air.Bridge.Branches.Lt.Kind.signed .bge = true ∧
      Air.Bridge.Branches.Lt.Kind.signed .bltu = false ∧
      Air.Bridge.Branches.Lt.Kind.signed .bgeu = false ∧
      Air.Bridge.Branches.Lt.signedLess
          highBitOperand.word WordBytes.zero.word = true ∧
      (decide (
          highBitOperand.word.toNat <
            WordBytes.zero.word.toNat) : Bool) = false := by
  decide

end Lt

end RiscvRefinement.Opcodes.Branches
