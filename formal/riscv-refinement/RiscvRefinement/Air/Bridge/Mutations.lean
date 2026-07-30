import RiscvRefinement.Air.Bridge.Addi
import RiscvRefinement.Mutation
import RiscvRefinement.Opcodes.Lui
import RiscvRefinement.Opcodes.Addi

/-!
# Publication-grade LUI/ADDI AIR mutation controls

These controls execute the generated production programs in Lean.  The LUI
low-limb, ADDI carry, and selector-relabel controls exhibit architectural
counterexamples.  The immediate-range and event-order controls use the strict
fallback because those obligations protect the untyped serialized
representation or ordered translation interface rather than a field of the
already-bounded typed row.
-/

namespace RiscvRefinement.Air.Bridge.Mutations

open RiscvRefinement
open RiscvRefinement.Air.Generated
open RiscvRefinement.Mutation

abbrev constraintsHoldExcept :=
  SymbolicEvaluation.constraintsHoldExcept

abbrev fixedLookupsHoldExcept :=
  SymbolicEvaluation.fixedLookupsHoldExcept

def selectorsAcceptedAs
    (evaluation : SymbolicEvaluation)
    (manifestId : Nat) :
    Bool :=
  evaluation.activeRow == 1 &&
    evaluation.opcodeSelector == M31.reduce manifestId

structure LuiCase where
  row : LuiRow
  witness : Lui.Witness row

def luiOriginal (test : LuiCase) : Prop :=
  Lui.Admission test.row ∧ Lui.Acceptance test.row test.witness

def luiDestinationCorrect (test : LuiCase) : Prop :=
  test.row.rdNext.word =
    architecturalValue test.row.rd
      (luiResult test.row.imm0 test.row.imm1 test.row.imm2)

theorem luiOriginal_sound
    (test : LuiCase)
    (original : luiOriginal test) :
    luiDestinationCorrect test := by
  rcases original with ⟨admission, accepted⟩
  have holds :=
    Lui.sound test.row test.witness admission accepted
  have destination :=
    RiscvRefinement.Opcodes.lui_destination_from_constraints
      (Lui.interpretedRow test.row) holds
  simpa [luiDestinationCorrect, Lui.interpretedRow] using destination

def luiLowLimbRow : LuiRow :=
  { Lui.exampleRow with
    rdNext := {
      WordBytes.zero with
      limb0 := BitVec.ofNat 8 1
    }
  }

def luiLowLimbCase : LuiCase where
  row := luiLowLimbRow
  witness := { destinationInverse := 1 }

def luiWithoutLowLimb (test : LuiCase) : Prop :=
  Lui.Admission test.row ∧
  (Lui.evaluation test.row test.witness).activeSelectorsAccepted = true ∧
  constraintsHoldExcept (Lui.evaluation test.row test.witness) 4 = true ∧
  (Lui.evaluation test.row test.witness).fixedLookupsHold = true

set_option maxRecDepth 30000 in
theorem luiLowLimb_satisfies :
    luiWithoutLowLimb luiLowLimbCase := by
  refine ⟨?_, Lui.selectorAccepted _ _, ?_, ?_⟩
  · constructor <;> decide
  · apply (Lui.constraintsHoldExceptLowLimb_iff _ _).mpr
    simp [
      Lui.ConstraintEquationsWithoutLowLimb,
      luiLowLimbCase,
      luiLowLimbRow,
      Lui.exampleRow,
      Lui.boolM31,
      Lui.bitVecM31,
      WordBytes.zero,
    ]
  · rw [Lui.fixedLookupsHold_eq]
    decide

theorem luiLowLimb_refutes :
    ¬ luiDestinationCorrect luiLowLimbCase := by
  intro equality
  have values := congrArg BitVec.toNat equality
  simp [
    luiLowLimbCase,
    luiLowLimbRow,
    Lui.exampleRow,
    WordBytes.word_toNat,
    WordBytes.value,
    WordBytes.zero,
    architecturalValue,
    zeroRegister,
    luiResult,
    luiImmediate,
  ] at values

def luiLowLimbControl :
    MutationControl luiWithoutLowLimb luiDestinationCorrect where
  name := "lui-free-low-limb"
  witness := luiLowLimbCase
  satisfies := luiLowLimb_satisfies
  refutes := luiLowLimb_refutes

theorem luiLowLimb_strictly_weaker :
    ¬ (∀ test, luiWithoutLowLimb test → luiOriginal test) :=
  luiLowLimbControl.strictly_weaker luiOriginal luiOriginal_sound

structure AddiCase where
  row : AddiRow
  witness : Addi.Witness row

def addiOriginal (test : AddiCase) : Prop :=
  Addi.Admission test.row ∧ Addi.Acceptance test.row test.witness

def addiArithmeticCorrect (test : AddiCase) : Prop :=
  test.row.result.word =
    addiResult
      test.row.rs1Next.word
      test.row.imm0
      test.row.imm1
      test.row.immSign

theorem addiOriginal_sound
    (test : AddiCase)
    (original : addiOriginal test) :
    addiArithmeticCorrect test := by
  rcases original with ⟨admission, accepted⟩
  have holds :=
    Addi.sound test.row test.witness admission accepted
  have arithmetic :=
    RiscvRefinement.Opcodes.addi_arithmetic_from_constraints
      (Addi.interpretedRow test.row) holds
  simpa [addiArithmeticCorrect, Addi.interpretedRow] using arithmetic

def addiCarryRow : AddiRow :=
  { Addi.exampleRow with
    rdNext := {
      WordBytes.zero with
      limb3 := BitVec.ofNat 8 1
    }
    result := {
      WordBytes.zero with
      limb3 := BitVec.ofNat 8 1
    }
  }

def addiCarryCase : AddiCase where
  row := addiCarryRow
  witness := { destinationInverse := 1 }

def addiWithoutHighCarry (test : AddiCase) : Prop :=
  Addi.Admission test.row ∧
  (Addi.evaluation test.row test.witness).activeSelectorsAccepted = true ∧
  constraintsHoldExcept (Addi.evaluation test.row test.witness) 9 = true ∧
  (Addi.evaluation test.row test.witness).fixedLookupsHold = true

set_option maxRecDepth 40000 in
theorem addiCarry_satisfies :
    addiWithoutHighCarry addiCarryCase := by
  refine ⟨?_, Addi.selectorAccepted _ _, ?_, ?_⟩
  · constructor <;> decide
  · apply (Addi.constraintsHoldExceptHighCarry_iff _ _).mpr
    simp [
      Addi.ConstraintEquationsWithoutHighCarry,
      addiCarryCase,
      addiCarryRow,
      Addi.exampleRow,
      Addi.boolM31,
      Addi.bitVecM31,
      Addi.carry1Field,
      Addi.carry2Field,
      Addi.carry3Field,
      Addi.immediateLimb1Field,
      Addi.signLimbField,
      Lui.boolM31,
      Lui.bitVecM31,
      WordBytes.zero,
    ]
  · rw [Addi.fixedLookupsHold_eq]
    decide

theorem addiCarry_refutes :
    ¬ addiArithmeticCorrect addiCarryCase := by
  intro equality
  have values := congrArg BitVec.toNat equality
  simp [
    addiCarryCase,
    addiCarryRow,
    Addi.exampleRow,
    WordBytes.word_toNat,
    WordBytes.value,
    WordBytes.zero,
    addiResult,
    addiAirImmediate,
    addiImmediateValue,
  ] at values

def addiCarryControl :
    MutationControl addiWithoutHighCarry addiArithmeticCorrect where
  name := "addi-free-high-carry"
  witness := addiCarryCase
  satisfies := addiCarry_satisfies
  refutes := addiCarry_refutes

theorem addiCarry_strictly_weaker :
    ¬ (∀ test, addiWithoutHighCarry test → addiOriginal test) :=
  addiCarryControl.strictly_weaker addiOriginal addiOriginal_sound

def immediateRangeColumns : Nat → M31
  | 0 => 1
  | 2 => 1
  | 9 => M31.reduce 8
  | 12 => M31.reduce 2
  | 23 => M31.reduce 8
  | 25 => 1
  | 30 => M31.reduce 8
  | 33 => 1
  | 34 => 1
  | _ => 0

def immediateRangeEvaluation : SymbolicEvaluation :=
  Programs.addi.evalSymbolic immediateRangeColumns

def rawAddiWithoutImmediateRange (columns : Nat → M31) : Prop :=
  (Programs.addi.evalSymbolic columns).lookup? 23 =
    some (Addi.immediateLookupForColumns columns)

def rawAddiOriginal (columns : Nat → M31) : Prop :=
  rawAddiWithoutImmediateRange columns ∧
    (Addi.immediateLookupForColumns columns).fixedRequestHolds = true

theorem immediateRange_satisfies :
    rawAddiWithoutImmediateRange immediateRangeColumns :=
  Addi.immediateLookup_projection_for_columns immediateRangeColumns

theorem immediateRange_refutes :
    ¬ rawAddiOriginal immediateRangeColumns := by
  intro original
  have rejected :
      (Addi.immediateLookupForColumns
        immediateRangeColumns).fixedRequestHolds = false := by
    decide
  simp only [rawAddiOriginal] at original
  rw [rejected] at original
  exact Bool.noConfusion original.2

theorem immediateRange_strictly_weaker :
    ¬ (∀ columns,
      rawAddiWithoutImmediateRange columns → rawAddiOriginal columns) :=
  strictly_weaker_of_not_original
    immediateRangeColumns
    immediateRange_satisfies
    immediateRange_refutes

def lowByteOne : WordBytes where
  limb0 := BitVec.ofNat 8 1
  limb1 := BitVec.ofNat 8 0
  limb2 := BitVec.ofNat 8 0
  limb3 := BitVec.ofNat 8 0

def selectorRelabelRow : AddiRow :=
  { Addi.exampleRow with
    rdNext := WordBytes.zero
    rs1Previous := lowByteOne
    rs1Next := lowByteOne
    imm0 := BitVec.ofNat 8 1
    result := WordBytes.zero
  }

def selectorRelabelCase : AddiCase where
  row := selectorRelabelRow
  witness := { destinationInverse := 1 }

def relabeledColumns (test : AddiCase) : Nat → M31
  | 25 => 0
  | 26 => 1
  | index => Addi.columns test.row test.witness index

def relabeledEvaluation (test : AddiCase) : SymbolicEvaluation :=
  Programs.addi.evalSymbolic (relabeledColumns test)

def addiWithXoriRelabel (test : AddiCase) : Prop :=
  Addi.Admission test.row ∧
  selectorsAcceptedAs (relabeledEvaluation test) 13 = true ∧
  (relabeledEvaluation test).lookup? 29 =
    some (Addi.bitwiseLookup0ForColumns (relabeledColumns test)) ∧
  (Addi.bitwiseLookup0ForColumns
    (relabeledColumns test)).fixedRequestHolds = true

set_option maxRecDepth 40000 in
theorem selectorRelabel_satisfies :
    addiWithXoriRelabel selectorRelabelCase := by
  refine ⟨?_, ?_, ?_, ?_⟩
  · change Addi.Admission selectorRelabelRow
    constructor <;> decide
  · rcases
      Addi.selector_projection_for_columns
        (relabeledColumns selectorRelabelCase) with
      ⟨activeRow, _, opcodeSelector⟩
    rw [selectorsAcceptedAs, relabeledEvaluation, activeRow, opcodeSelector]
    simp [
      relabeledColumns,
      Addi.columns,
      Addi.activeRowForColumns,
      Addi.opcodeSelectorForColumns,
    ]
  · exact
      Addi.bitwiseLookup0_projection_for_columns
        (relabeledColumns selectorRelabelCase)
  · change
      (Addi.bitwiseLookup0ForColumns
        (relabeledColumns selectorRelabelCase)).fixedRequestHolds = true
    simp [
      relabeledColumns,
      selectorRelabelCase,
      selectorRelabelRow,
      lowByteOne,
      Addi.columns,
      Addi.exampleRow,
      Addi.bitVecM31,
      Lui.bitVecM31,
      Addi.bitwiseLookup0ForColumns,
      EvaluatedLookup.fixedRequestHolds,
      EvaluatedLookup.fixedMembership,
      EvaluatedLookup.isLive,
      FixedTableId.contains,
      WordBytes.zero,
    ]
    decide

theorem selectorRelabel_refutes :
    ¬ addiArithmeticCorrect selectorRelabelCase := by
  intro equality
  have values := congrArg BitVec.toNat equality
  simp [
    selectorRelabelCase,
    selectorRelabelRow,
    lowByteOne,
    Addi.exampleRow,
    WordBytes.word_toNat,
    WordBytes.value,
    WordBytes.zero,
    addiResult,
    addiAirImmediate,
    addiImmediateValue,
  ] at values

def selectorRelabelControl :
    MutationControl addiWithXoriRelabel addiArithmeticCorrect where
  name := "addi-selector-relabel-xori"
  witness := selectorRelabelCase
  satisfies := selectorRelabel_satisfies
  refutes := selectorRelabel_refutes

theorem selectorRelabel_strictly_weaker :
    ¬ (∀ test, addiWithXoriRelabel test → addiOriginal test) :=
  selectorRelabelControl.strictly_weaker addiOriginal addiOriginal_sound

private theorem all_swapIfInBounds_of_all
    {α : Type}
    (values : Array α)
    (predicate : α → Bool)
    (left right : Nat)
    (accepted : values.all predicate = true) :
    (values.swapIfInBounds left right).all predicate = true := by
  rw [Array.all_eq_true] at accepted ⊢
  intro index bound
  rw [Array.getElem_swapIfInBounds]
  split
  · rename_i atLeft
    exact accepted right atLeft.2
  · split
    · rename_i atRight
      exact accepted left atRight.2
    · exact accepted index (by simpa using bound)

private theorem eventAt_of_lookup
    (evaluation : SymbolicEvaluation)
    (ordinal : Nat)
    (lookup : EvaluatedLookup)
    (projection : evaluation.lookup? ordinal = some lookup) :
    evaluation.events[ordinal]? = some (.lookup lookup) := by
  rw [SymbolicEvaluation.lookup?, Option.bind_eq_some_iff] at projection
  obtain ⟨event, eventAt, eventLookup⟩ := projection
  cases event with
  | constraint constraint =>
      simp only [EvaluatedEvent.lookup?] at eventLookup
      cases eventLookup
  | lookup actual =>
      simp only [EvaluatedEvent.lookup?, Option.some.injEq] at eventLookup
      subst actual
      exact eventAt

def reorderedEvaluation : SymbolicEvaluation :=
  let original := Addi.evaluation Addi.exampleRow Addi.exampleWitness
  { original with
    events := original.events.swapIfInBounds 22 23
  }

def genericallyAccepted (evaluation : SymbolicEvaluation) : Prop :=
  evaluation.activeSelectorsAccepted = true ∧
  evaluation.constraintsHold = true ∧
  evaluation.fixedLookupsHold = true

def addiEventOrderCorrect (evaluation : SymbolicEvaluation) : Prop :=
  evaluation.lookup? 22 = some (Addi.programLookup Addi.exampleRow) ∧
  evaluation.lookup? 23 = some (Addi.immediateLookup Addi.exampleRow)

def addiOrderedAcceptance (evaluation : SymbolicEvaluation) : Prop :=
  genericallyAccepted evaluation ∧ addiEventOrderCorrect evaluation

set_option maxRecDepth 40000 in
theorem reordered_satisfies :
    genericallyAccepted reorderedEvaluation := by
  have accepted := Addi.exampleAcceptance
  refine ⟨?_, ?_, ?_⟩
  · simpa [reorderedEvaluation] using accepted.selectors
  · rw [reorderedEvaluation, SymbolicEvaluation.constraintsHold]
    exact
      all_swapIfInBounds_of_all
        (Addi.evaluation Addi.exampleRow Addi.exampleWitness).events
        (fun
          | .constraint event => event.value == 0
          | .lookup _ => true)
        22 23
        (by
          simpa [SymbolicEvaluation.constraintsHold] using
            accepted.constraints)
  · rw [reorderedEvaluation, SymbolicEvaluation.fixedLookupsHold]
    exact
      all_swapIfInBounds_of_all
        (Addi.evaluation Addi.exampleRow Addi.exampleWitness).events
        (fun
          | .constraint _ => true
          | .lookup event => event.fixedRequestHolds)
        22 23
        (by
          simpa [SymbolicEvaluation.fixedLookupsHold] using
            accepted.fixedLookups)

set_option maxRecDepth 40000 in
theorem reordered_refutes :
    ¬ addiOrderedAcceptance reorderedEvaluation := by
  intro accepted
  have ordered := accepted.2
  have programAt := ordered.1
  let original :=
    Addi.evaluation Addi.exampleRow Addi.exampleWitness
  have projections :=
    Addi.lookup_projection Addi.exampleRow Addi.exampleWitness
  have originalProgramAt :
      original.events[22]? =
        some (.lookup (Addi.programLookup Addi.exampleRow)) :=
    eventAt_of_lookup
      original 22 (Addi.programLookup Addi.exampleRow) projections.1
  have originalImmediateAt :
      original.events[23]? =
        some (.lookup (Addi.immediateLookup Addi.exampleRow)) :=
    eventAt_of_lookup
      original 23 (Addi.immediateLookup Addi.exampleRow) projections.2.1
  obtain ⟨programBound, _⟩ :=
    Array.getElem?_eq_some_iff.mp originalProgramAt
  obtain ⟨immediateBound, immediateValue⟩ :=
    Array.getElem?_eq_some_iff.mp originalImmediateAt
  have swappedAt :
      (original.events.swapIfInBounds 22 23)[22]? =
        some (.lookup (Addi.immediateLookup Addi.exampleRow)) := by
    apply Array.getElem?_eq_some_iff.mpr
    refine ⟨?_, ?_⟩
    · simpa using programBound
    · rw [Array.getElem_swapIfInBounds_left immediateBound]
      exact immediateValue
  have reorderedLookup :
      reorderedEvaluation.lookup? 22 =
        some (Addi.immediateLookup Addi.exampleRow) := by
    change
      ((original.events.swapIfInBounds 22 23)[22]?).bind
          EvaluatedEvent.lookup? =
        some (Addi.immediateLookup Addi.exampleRow)
    rw [swappedAt]
    rfl
  rw [reorderedLookup] at programAt
  have distinct :
      Addi.immediateLookup Addi.exampleRow ≠
        Addi.programLookup Addi.exampleRow := by
    decide
  exact distinct (Option.some.inj programAt)

theorem reordered_strictly_weaker :
    ¬ (∀ evaluation,
      genericallyAccepted evaluation → addiOrderedAcceptance evaluation) :=
  strictly_weaker_of_not_original
    reorderedEvaluation
    reordered_satisfies
    reordered_refutes

end RiscvRefinement.Air.Bridge.Mutations
