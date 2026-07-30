import RiscvRefinement.Air.Decode
import RiscvRefinement.Air.Eval

namespace RiscvRefinement.Air

open RiscvRefinement

/-!
# Symbolically scalable AIR expression evaluation

The wire format uses absolute, forward-only node IDs. Repeated symbolic
evaluation through `Array.push` makes Lean rebuild a growing array for every
reference. `LocalExprNode` is a checked, derived view of the same DAG: an
argument is stored as its offset from the head of a newest-first value list.
The evaluator can therefore use constant-shape `List.get?` reads and a cons
accumulator.

Localization is not a second semantic input. It is computed in Lean from the
strictly decoded `ConstraintProgram`, rejects every non-backward reference,
and preserves constants, columns, and operations exactly.
-/

inductive LocalExprNode where
  | const (value : M31)
  | column (column : Nat)
  | add (left right : Nat)
  | sub (left right : Nat)
  | mul (left right : Nat)
  | neg (value : Nat)
deriving DecidableEq, Repr

private def localReference
    (index reference : Nat) :
    Except EvalError Nat :=
  if reference < index then
    .ok (index - reference - 1)
  else
    .error (.invalidNodeReference reference)

def ExprNode.localize
    (index : Nat) :
    ExprNode → Except EvalError LocalExprNode
  | ExprNode.const value => .ok (.const value)
  | ExprNode.column columnIndex => .ok (.column columnIndex)
  | ExprNode.add left right =>
      return .add (← localReference index left) (← localReference index right)
  | ExprNode.sub left right =>
      return .sub (← localReference index left) (← localReference index right)
  | ExprNode.mul left right =>
      return .mul (← localReference index left) (← localReference index right)
  | ExprNode.neg value => return .neg (← localReference index value)

private def localizeFrom :
    Nat → List ExprNode → Except EvalError (List LocalExprNode)
  | _, [] => .ok []
  | index, node :: tail => do
      return (← node.localize index) :: (← localizeFrom (index + 1) tail)

def ConstraintProgram.localNodes
    (program : ConstraintProgram) :
    Except EvalError (List LocalExprNode) :=
  localizeFrom 0 program.nodes.toList

def newestValue
    (valuesRev : List M31) :
    Nat → Except EvalError M31
  | 0 =>
      match valuesRev with
      | value :: _ => .ok value
      | [] => .error (.invalidNodeReference 0)
  | offset + 1 =>
      match valuesRev with
      | _ :: tail => newestValue tail offset
      | [] => .error (.invalidNodeReference (offset + 1))

def LocalExprNode.eval
    (row : Array M31)
    (valuesRev : List M31) :
    LocalExprNode → Except EvalError M31
  | .const value => .ok value
  | .column columnIndex =>
      match row[columnIndex]? with
      | some value => .ok value
      | none => .error (.missingColumn columnIndex)
  | .add left right =>
      return (← newestValue valuesRev left) + (← newestValue valuesRev right)
  | .sub left right =>
      return (← newestValue valuesRev left) - (← newestValue valuesRev right)
  | .mul left right =>
      return (← newestValue valuesRev left) * (← newestValue valuesRev right)
  | .neg value => return -(← newestValue valuesRev value)

def LocalExprNode.evalAll
    (row : Array M31) :
    List LocalExprNode → List M31 → Except EvalError (List M31)
  | [], valuesRev => .ok valuesRev
  | node :: tail, valuesRev => do
      let value ← node.eval row valuesRev
      evalAll row tail (value :: valuesRev)

/--
The theorem-facing evaluator.  Generated programs have already checked every
column and back-offset, so their symbolic evaluation does not need to retain
an `Array.get?`/`Except` branch at every node.  The zero fallbacks are
unreachable for a valid generated program; `evalSymbolic_eq_eval` below makes
that relationship explicit.
-/
def newestValueSymbolic
    (valuesRev : List M31) :
    Nat → M31
  | 0 =>
      match valuesRev with
      | value :: _ => value
      | [] => 0
  | offset + 1 =>
      match valuesRev with
      | _ :: tail => newestValueSymbolic tail offset
      | [] => 0

def LocalExprNode.evalSymbolic
    (row : Nat → M31)
    (valuesRev : List M31) :
    LocalExprNode → M31
  | .const value => value
  | .column columnIndex => row columnIndex
  | .add left right =>
      newestValueSymbolic valuesRev left +
        newestValueSymbolic valuesRev right
  | .sub left right =>
      newestValueSymbolic valuesRev left -
        newestValueSymbolic valuesRev right
  | .mul left right =>
      newestValueSymbolic valuesRev left *
        newestValueSymbolic valuesRev right
  | .neg value => -(newestValueSymbolic valuesRev value)

def LocalExprNode.evalAllSymbolic
    (row : Nat → M31) :
    List LocalExprNode → List M31 → List M31
  | [], valuesRev => valuesRev
  | node :: tail, valuesRev =>
      evalAllSymbolic row tail (node.evalSymbolic row valuesRev :: valuesRev)

def LocalExprNode.validAt
    (columnCount valueCount : Nat) :
    LocalExprNode → Bool
  | .const _ => true
  | .column columnIndex => columnIndex < columnCount
  | .add left right
  | .sub left right
  | .mul left right => left < valueCount && right < valueCount
  | .neg value => value < valueCount

def LocalExprNode.validFrom
    (columnCount : Nat) :
    Nat → List LocalExprNode → Bool
  | _, [] => true
  | valueCount, node :: tail =>
      node.validAt columnCount valueCount &&
        validFrom columnCount (valueCount + 1) tail

theorem newestValue_eq_symbolic
    (valuesRev : List M31)
    (offset : Nat)
    (valid : offset < valuesRev.length) :
    newestValue valuesRev offset =
      .ok (newestValueSymbolic valuesRev offset) := by
  induction valuesRev generalizing offset with
  | nil => simp at valid
  | cons value tail induction =>
      cases offset with
      | zero => rfl
      | succ offset =>
          simp only [newestValue, newestValueSymbolic]
          apply induction
          simpa using valid

theorem LocalExprNode.eval_eq_symbolic
    (node : LocalExprNode)
    (row : Array M31)
    (rowSymbolic : Nat → M31)
    (valuesRev : List M31)
    (columnCount : Nat)
    (valid : node.validAt columnCount valuesRev.length = true)
    (rowBinds :
      ∀ columnIndex, columnIndex < columnCount →
        row[columnIndex]? = some (rowSymbolic columnIndex)) :
    node.eval row valuesRev =
      .ok (node.evalSymbolic rowSymbolic valuesRev) := by
  cases node with
  | const value => rfl
  | column columnIndex =>
      simp only [validAt] at valid
      simp only [eval, evalSymbolic, rowBinds columnIndex (by simpa using valid)]
  | add left right =>
      simp only [validAt, Bool.and_eq_true] at valid
      rw [
        eval,
        evalSymbolic,
        newestValue_eq_symbolic valuesRev left (by simpa using valid.1),
        newestValue_eq_symbolic valuesRev right (by simpa using valid.2),
      ]
      rfl
  | sub left right =>
      simp only [validAt, Bool.and_eq_true] at valid
      rw [
        eval,
        evalSymbolic,
        newestValue_eq_symbolic valuesRev left (by simpa using valid.1),
        newestValue_eq_symbolic valuesRev right (by simpa using valid.2),
      ]
      rfl
  | mul left right =>
      simp only [validAt, Bool.and_eq_true] at valid
      rw [
        eval,
        evalSymbolic,
        newestValue_eq_symbolic valuesRev left (by simpa using valid.1),
        newestValue_eq_symbolic valuesRev right (by simpa using valid.2),
      ]
      rfl
  | neg value =>
      simp only [validAt] at valid
      rw [
        eval,
        evalSymbolic,
        newestValue_eq_symbolic valuesRev value (by simpa using valid),
      ]
      rfl

theorem LocalExprNode.evalAll_eq_symbolic
    (nodes : List LocalExprNode)
    (row : Array M31)
    (rowSymbolic : Nat → M31)
    (valuesRev : List M31)
    (columnCount : Nat)
    (valid :
      validFrom columnCount valuesRev.length nodes = true)
    (rowBinds :
      ∀ columnIndex, columnIndex < columnCount →
        row[columnIndex]? = some (rowSymbolic columnIndex)) :
    evalAll row nodes valuesRev =
      .ok (evalAllSymbolic rowSymbolic nodes valuesRev) := by
  induction nodes generalizing valuesRev with
  | nil => rfl
  | cons node tail induction =>
      simp only [validFrom, Bool.and_eq_true] at valid
      rw [
        evalAll,
        node.eval_eq_symbolic
          row rowSymbolic valuesRev columnCount valid.1 rowBinds,
        evalAllSymbolic,
      ]
      apply induction
      simpa using valid.2

structure LocalValues where
  count : Nat
  valuesRev : List M31
deriving DecidableEq, Repr

namespace LocalValues

def get
    (values : LocalValues)
    (node : NodeId) :
    Except EvalError M31 :=
  if node < values.count then
    newestValue values.valuesRev (values.count - node - 1)
  else
    .error (.invalidNodeReference node)

def getSymbolic
    (values : LocalValues)
    (node : NodeId) :
    M31 :=
  newestValueSymbolic values.valuesRev (values.count - node - 1)

theorem get_eq_symbolic
    (values : LocalValues)
    (node : NodeId)
    (count : values.valuesRev.length = values.count)
    (valid : node < values.count) :
    values.get node = .ok (values.getSymbolic node) := by
  rw [get, getSymbolic]
  simp only [valid, ↓reduceIte]
  apply newestValue_eq_symbolic
  rw [count]
  calc
    values.count - node - 1 < values.count - node :=
      Nat.sub_lt (Nat.sub_pos_of_lt valid) (by decide)
    _ ≤ values.count := Nat.sub_le values.count node

end LocalValues

structure LocalProgram where
  source : ConstraintProgram
  nodes : List LocalExprNode
deriving DecidableEq, Repr

namespace LocalProgram

def eventReferencesBelow
    (nodeCount : Nat) :
    Event → Bool
  | .constraint event => event.root < nodeCount
  | .lookup event =>
      event.numerator < nodeCount &&
        event.tuple.all fun node => node < nodeCount

def projectionReferencesBelow
    (nodeCount eventCount : Nat)
    (projection : Projection) :
    Bool :=
  projection.programEvent < eventCount &&
    projection.stateEvents.all fun ordinal => ordinal < eventCount &&
    projection.sourceEvents.all fun ordinal => ordinal < eventCount &&
    projection.destinationEvents.all fun ordinal => ordinal < eventCount &&
    projection.nextPc < nodeCount

structure SymbolicCertificate (program : LocalProgram) : Prop where
  localization : program.source.localNodes = .ok program.nodes
  valid :
    LocalExprNode.validFrom program.source.columns.size 0 program.nodes = true
  nodeCount : program.nodes.length = program.source.nodes.size
  activeRow : program.source.activeRow < program.source.nodes.size
  selector :
    program.source.opcodeSelector.expression < program.source.nodes.size
  events :
    program.source.events.all
      (eventReferencesBelow program.source.nodes.size) = true
  projection :
    projectionReferencesBelow
      program.source.nodes.size program.source.events.size
      program.source.projection = true

def bindingValid (program : LocalProgram) : Bool :=
  match program.source.localNodes with
  | .error _ => false
  | .ok nodes => decide (nodes = program.nodes)

def matchesCanonicalJson
    (program : LocalProgram)
    (encoded : String) :
    Bool :=
  match ConstraintProgram.decodeCanonical encoded with
  | .error _ => false
  | .ok decoded =>
      decide (decoded = program.source) && program.bindingValid

def evalNodes
    (program : LocalProgram)
    (row : Array M31) :
    Except EvalError LocalValues := do
  let valuesRev ← LocalExprNode.evalAll row program.nodes []
  return {
    count := program.source.nodes.size
    valuesRev
  }

def evalNodesSymbolic
    (program : LocalProgram)
    (row : Nat → M31) :
    LocalValues := {
  count := program.nodes.length
  valuesRev := LocalExprNode.evalAllSymbolic row program.nodes []
}

theorem evalNodes_eq_symbolic
    (program : LocalProgram)
    (certificate : program.SymbolicCertificate)
    (row : Array M31)
    (rowSymbolic : Nat → M31)
    (rowBinds :
      ∀ columnIndex, columnIndex < program.source.columns.size →
        row[columnIndex]? = some (rowSymbolic columnIndex)) :
    program.evalNodes row = .ok (program.evalNodesSymbolic rowSymbolic) := by
  rw [evalNodes, evalNodesSymbolic]
  rw [
    LocalExprNode.evalAll_eq_symbolic
      program.nodes row rowSymbolic [] program.source.columns.size
      (by simpa using certificate.valid)
      rowBinds,
  ]
  rw [certificate.nodeCount]
  rfl

end LocalProgram

def Event.evalSymbolic
    (values : LocalValues) :
    Event → EvaluatedEvent
  | .constraint event =>
      .constraint {
        ordinal := event.ordinal
        value := values.getSymbolic event.root
      }
  | .lookup event =>
      .lookup {
        ordinal := event.ordinal
        domain := event.domain
        numerator := values.getSymbolic event.numerator
        tuple := event.tuple.map values.getSymbolic
        role := event.role
        tableId := event.tableId
        accessOrdinal := event.accessOrdinal
      }

structure SymbolicEvaluation where
  activeRow : M31
  manifestId : Nat
  opcodeSelector : M31
  nodes : LocalValues
  events : Array EvaluatedEvent
deriving DecidableEq, Repr

namespace SymbolicEvaluation

def rowActive (evaluation : SymbolicEvaluation) : Bool :=
  evaluation.activeRow == 1

def activeSelectorsAccepted (evaluation : SymbolicEvaluation) : Bool :=
  evaluation.activeRow == 1 &&
  match M31.ofNat? evaluation.manifestId with
  | some manifestId => evaluation.opcodeSelector == manifestId
  | none => false

def constraintsHold (evaluation : SymbolicEvaluation) : Bool :=
  evaluation.events.all fun
    | .constraint event => event.value == 0
    | .lookup _ => true

/-- Mutation-audit variant of `constraintsHold` that disables exactly one
event ordinal while continuing to evaluate every other production event. -/
def constraintsHoldExcept
    (evaluation : SymbolicEvaluation)
    (omittedOrdinal : EventOrdinal) :
    Bool :=
  evaluation.events.all fun
    | .constraint event =>
        if event.ordinal == omittedOrdinal then true else event.value == 0
    | .lookup _ => true

def liveLookups (evaluation : SymbolicEvaluation) : Array EvaluatedLookup :=
  if evaluation.activeSelectorsAccepted then
    evaluation.events.filterMap fun
      | .constraint _ => none
      | .lookup event => if event.isLive then some event else none
  else
    #[]

def fixedLookupsHold (evaluation : SymbolicEvaluation) : Bool :=
  evaluation.events.all fun
    | .constraint _ => true
    | .lookup event => event.fixedRequestHolds

/-- Mutation-audit variant of `fixedLookupsHold` that disables exactly one
lookup ordinal while preserving every other fixed-table check. -/
def fixedLookupsHoldExcept
    (evaluation : SymbolicEvaluation)
    (omittedOrdinal : EventOrdinal) :
    Bool :=
  evaluation.events.all fun
    | .constraint _ => true
    | .lookup event =>
        if event.ordinal == omittedOrdinal
        then true
        else event.fixedRequestHolds

def lookup? (evaluation : SymbolicEvaluation) (ordinal : EventOrdinal) :
    Option EvaluatedLookup :=
  (evaluation.events[ordinal]?).bind EvaluatedEvent.lookup?

theorem fixedRequestHolds_of_lookup
    (evaluation : SymbolicEvaluation)
    (ordinal : EventOrdinal)
    (lookup : EvaluatedLookup)
    (allFixed : evaluation.fixedLookupsHold = true)
    (selected : evaluation.lookup? ordinal = some lookup) :
    lookup.fixedRequestHolds = true := by
  rw [fixedLookupsHold, Array.all_eq_true] at allFixed
  rw [lookup?, Option.bind_eq_some_iff] at selected
  obtain ⟨event, eventAt, eventLookup⟩ := selected
  obtain ⟨bound, eventValue⟩ :=
    Array.getElem?_eq_some_iff.mp eventAt
  have accepted := allFixed ordinal bound
  rw [eventValue] at accepted
  cases event with
  | constraint event =>
      simp only [EvaluatedEvent.lookup?] at eventLookup
      cases eventLookup
  | lookup actual =>
      simp only [EvaluatedEvent.lookup?, Option.some.injEq] at eventLookup
      subst actual
      exact accepted

end SymbolicEvaluation

def LocalProgram.evalSymbolic
    (program : LocalProgram)
    (row : Nat → M31) :
    SymbolicEvaluation :=
  let nodes := program.evalNodesSymbolic row
  {
    activeRow := nodes.getSymbolic program.source.activeRow
    manifestId := program.source.opcodeSelector.manifestId
    opcodeSelector :=
      nodes.getSymbolic program.source.opcodeSelector.expression
    nodes
    events := program.source.events.map (Event.evalSymbolic nodes)
  }

theorem LocalProgram.lookup?_evalSymbolic_of_event
    (program : LocalProgram)
    (row : Nat → M31)
    (ordinal : EventOrdinal)
    (event : LookupEvent)
    (selected :
      program.source.events[ordinal]? = some (.lookup event)) :
    (program.evalSymbolic row).lookup? ordinal =
      some {
        ordinal := event.ordinal
        domain := event.domain
        numerator :=
          (program.evalNodesSymbolic row).getSymbolic event.numerator
        tuple :=
          event.tuple.map
            (program.evalNodesSymbolic row).getSymbolic
        role := event.role
        tableId := event.tableId
        accessOrdinal := event.accessOrdinal
      } := by
  simp only [
    evalSymbolic,
    SymbolicEvaluation.lookup?,
    Array.getElem?_map,
    selected,
    Option.map,
    Event.evalSymbolic,
    Option.bind,
    EvaluatedEvent.lookup?,
  ]

def ConstraintProgram.localize
    (program : ConstraintProgram) :
    Except EvalError LocalProgram := do
  return {
    source := program
    nodes := ← program.localNodes
  }

def ConstraintProgram.evalLocalNodes
    (program : ConstraintProgram)
    (row : Array M31) :
    Except EvalError LocalValues := do
  let localized ← program.localize
  localized.evalNodes row

private def evalLocalTuple
    (values : LocalValues)
    (tuple : Array NodeId) :
    Except EvalError (Array M31) :=
  tuple.mapM values.get

def Event.evalLocal
    (values : LocalValues) :
    Event → Except EvalError EvaluatedEvent
  | .constraint event =>
      return .constraint {
        ordinal := event.ordinal
        value := ← values.get event.root
      }
  | .lookup event =>
      return .lookup {
        ordinal := event.ordinal
        domain := event.domain
        numerator := ← values.get event.numerator
        tuple := ← evalLocalTuple values event.tuple
        role := event.role
        tableId := event.tableId
        accessOrdinal := event.accessOrdinal
      }

private def projectedLocalLookup
    (events : Array EvaluatedEvent)
    (ordinal : EventOrdinal) :
    Except EvalError EvaluatedLookup :=
  match (events[ordinal]?).bind EvaluatedEvent.lookup? with
  | some lookup => .ok lookup
  | none => .error (.projectionNotLookup ordinal)

private def projectedLocalLookups
    (events : Array EvaluatedEvent)
    (ordinals : Array EventOrdinal) :
    Except EvalError (Array EvaluatedLookup) :=
  ordinals.mapM (projectedLocalLookup events)

def Projection.evalLocal
    (projection : Projection)
    (values : LocalValues)
    (events : Array EvaluatedEvent) :
    Except EvalError EvaluatedProjection := do
  return {
    programEvent := ← projectedLocalLookup events projection.programEvent
    stateEvents := ← projectedLocalLookups events projection.stateEvents
    sourceEvents := ← projectedLocalLookups events projection.sourceEvents
    destinationEvents :=
      ← projectedLocalLookups events projection.destinationEvents
    nextPc := ← values.get projection.nextPc
  }

def LocalProgram.eval
    (program : LocalProgram)
    (row : Array M31) :
    Except EvalError EvaluatedProgram := do
  let values ← program.evalNodes row
  let events ← program.source.events.mapM (Event.evalLocal values)
  return {
    activeRow := ← values.get program.source.activeRow
    manifestId := program.source.opcodeSelector.manifestId
    opcodeSelector := ← values.get program.source.opcodeSelector.expression
    nodes := values.valuesRev.reverse.toArray
    events
    projection := ← program.source.projection.evalLocal values events
  }

def ConstraintProgram.evalLocal
    (program : ConstraintProgram)
    (row : Array M31) :
    Except EvalError EvaluatedProgram := do
  let localized ← program.localize
  localized.eval row

end RiscvRefinement.Air
