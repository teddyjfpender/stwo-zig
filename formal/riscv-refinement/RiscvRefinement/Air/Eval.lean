import RiscvRefinement.Air.IR

namespace RiscvRefinement.Air

open RiscvRefinement

inductive EvalError where
  | missingColumn (index : Nat)
  | invalidNodeReference (node : NodeId)
  | projectionNotLookup (ordinal : EventOrdinal)
deriving DecidableEq, Repr

private def nodeValue
    (values : Array M31)
    (node : NodeId) :
    Except EvalError M31 :=
  match values[node]? with
  | some value => .ok value
  | none => .error (.invalidNodeReference node)

def ExprNode.eval
    (row : Array M31)
    (values : Array M31) :
    ExprNode → Except EvalError M31
  | .const value => .ok value
  | .column columnIndex =>
      match row[columnIndex]? with
      | some value => .ok value
      | none => .error (.missingColumn columnIndex)
  | .add left right => return (← nodeValue values left) + (← nodeValue values right)
  | .sub left right => return (← nodeValue values left) - (← nodeValue values right)
  | .mul left right => return (← nodeValue values left) * (← nodeValue values right)
  | .neg value => return -(← nodeValue values value)

def ConstraintProgram.evalNodes
    (program : ConstraintProgram)
    (row : Array M31) :
    Except EvalError (Array M31) :=
  program.nodes.foldlM (init := #[]) fun values node => do
    return values.push (← node.eval row values)

structure EvaluatedConstraint where
  ordinal : EventOrdinal
  value : M31
deriving DecidableEq, Repr

structure EvaluatedLookup where
  ordinal : EventOrdinal
  domain : Domain
  numerator : M31
  tuple : Array M31
  role : LookupRole
  tableId : Option FixedTableId
  accessOrdinal : Option Nat
deriving DecidableEq, Repr

namespace EvaluatedLookup

/-- The v2 liveness tag means exactly a nonzero evaluated numerator. -/
def isLive (lookup : EvaluatedLookup) : Bool :=
  lookup.numerator != 0

def fixedMembership (lookup : EvaluatedLookup) : Option Bool :=
  lookup.tableId.map fun table => table.contains lookup.tuple.toList

def fixedRequestHolds (lookup : EvaluatedLookup) : Bool :=
  if lookup.isLive then lookup.fixedMembership.getD true else true

end EvaluatedLookup

inductive EvaluatedEvent where
  | constraint (event : EvaluatedConstraint)
  | lookup (event : EvaluatedLookup)
deriving DecidableEq, Repr

namespace EvaluatedEvent

def ordinal : EvaluatedEvent → EventOrdinal
  | .constraint event => event.ordinal
  | .lookup event => event.ordinal

def lookup? : EvaluatedEvent → Option EvaluatedLookup
  | .constraint _ => none
  | .lookup event => some event

end EvaluatedEvent

private def evalTuple
    (values : Array M31)
    (tuple : Array NodeId) :
    Except EvalError (Array M31) :=
  tuple.mapM (nodeValue values)

def Event.eval
    (values : Array M31) :
    Event → Except EvalError EvaluatedEvent
  | .constraint event =>
      return .constraint {
        ordinal := event.ordinal
        value := ← nodeValue values event.root
      }
  | .lookup event =>
      return .lookup {
        ordinal := event.ordinal
        domain := event.domain
        numerator := ← nodeValue values event.numerator
        tuple := ← evalTuple values event.tuple
        role := event.role
        tableId := event.tableId
        accessOrdinal := event.accessOrdinal
      }

structure EvaluatedProjection where
  programEvent : EvaluatedLookup
  stateEvents : Array EvaluatedLookup
  sourceEvents : Array EvaluatedLookup
  destinationEvents : Array EvaluatedLookup
  nextPc : M31
deriving DecidableEq, Repr

private def projectedLookup
    (events : Array EvaluatedEvent)
    (ordinal : EventOrdinal) :
    Except EvalError EvaluatedLookup :=
  match (events[ordinal]?).bind EvaluatedEvent.lookup? with
  | some lookup => .ok lookup
  | none => .error (.projectionNotLookup ordinal)

private def projectedLookups
    (events : Array EvaluatedEvent)
    (ordinals : Array EventOrdinal) :
    Except EvalError (Array EvaluatedLookup) :=
  ordinals.mapM (projectedLookup events)

def Projection.eval
    (projection : Projection)
    (values : Array M31)
    (events : Array EvaluatedEvent) :
    Except EvalError EvaluatedProjection := do
  return {
    programEvent := ← projectedLookup events projection.programEvent
    stateEvents := ← projectedLookups events projection.stateEvents
    sourceEvents := ← projectedLookups events projection.sourceEvents
    destinationEvents := ← projectedLookups events projection.destinationEvents
    nextPc := ← nodeValue values projection.nextPc
  }

structure EvaluatedProgram where
  activeRow : M31
  manifestId : Nat
  opcodeSelector : M31
  nodes : Array M31
  events : Array EvaluatedEvent
  projection : EvaluatedProjection
deriving DecidableEq, Repr

namespace EvaluatedProgram

def rowActive (evaluation : EvaluatedProgram) : Bool :=
  evaluation.activeRow == 1

/--
Selector-specific acceptance requires the family active row to be one and the
program opcode-ID expression to equal the manifest ID in M31.
-/
def activeSelectorsAccepted (evaluation : EvaluatedProgram) : Bool :=
  evaluation.activeRow == 1 &&
  match M31.ofNat? evaluation.manifestId with
  | some manifestId => evaluation.opcodeSelector == manifestId
  | none => false

def constraintsHold (evaluation : EvaluatedProgram) : Bool :=
  evaluation.events.all fun
    | .constraint event => event.value == 0
    | .lookup _ => true

def liveLookups (evaluation : EvaluatedProgram) : Array EvaluatedLookup :=
  if evaluation.activeSelectorsAccepted then
    evaluation.events.filterMap fun
      | .constraint _ => none
      | .lookup event => if event.isLive then some event else none
  else
    #[]

def fixedLookupsHold (evaluation : EvaluatedProgram) : Bool :=
  evaluation.events.all fun
    | .constraint _ => true
    | .lookup event => event.fixedRequestHolds

end EvaluatedProgram

def ConstraintProgram.eval
    (program : ConstraintProgram)
    (row : Array M31) :
    Except EvalError EvaluatedProgram := do
  let nodes ← program.evalNodes row
  let events ← program.events.mapM (Event.eval nodes)
  return {
    activeRow := ← nodeValue nodes program.activeRow
    manifestId := program.opcodeSelector.manifestId
    opcodeSelector := ← nodeValue nodes program.opcodeSelector.expression
    nodes
    events
    projection := ← program.projection.eval nodes events
  }

end RiscvRefinement.Air
