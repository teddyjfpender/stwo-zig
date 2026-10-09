import S31.Semantics.Words

namespace S31.Graph

/-- A straight-line schedule. Operand indices address the input prefix followed
by previously produced wires. Hash algorithms construct these schedules; the
constraint layer gives each primitive an independent relation on its witnesses. -/
inductive Gate (α : Type) (Op : Type) where
  | constant (value : α)
  | apply (op : Op) (args : List Nat)
deriving Repr

structure Code (α : Type) (Op : Type) where
  gates : List (Gate α Op)
  outputs : List Nat
deriving Repr

structure Builder (α : Type) (Op : Type) where
  inputCount : Nat
  gates : Array (Gate α Op) := #[]

abbrev Build (α : Type) (Op : Type) := StateM (Builder α Op)

variable {α : Type} {Op : Type}

def emit (g : Gate α Op) : Build α Op Nat := do
  let state ← get
  let index := state.inputCount + state.gates.size
  set { state with gates := state.gates.push g }
  return index

def literal (x : α) : Build α Op Nat := emit (.constant x)
def unary (op : Op) (x : Nat) : Build α Op Nat := emit (.apply op [x])
def binary (op : Op) (x y : Nat) : Build α Op Nat := emit (.apply op [x, y])

def build (inputs : Nat) (program : Build α Op (List Nat)) : Code α Op :=
  let (outputs, state) := program.run ⟨inputs, #[]⟩
  ⟨state.gates.toList, outputs⟩

def Gate.eval [Inhabited α] (interpret : Op → List α → α)
    (values : List α) : Gate α Op → α
  | .constant x => x
  | .apply op args => interpret op (args.map (values.getD · default))

def run [Inhabited α] (interpret : Op → List α → α) :
    List (Gate α Op) → List α → List α
  | [], values => values
  | gate :: gates, values => run interpret gates (values ++ [gate.eval interpret values])

def Code.eval [Inhabited α] (code : Code α Op)
    (interpret : Op → List α → α) (inputs : List α) : List α :=
  let values := run interpret code.gates inputs
  code.outputs.map (values.getD · default)

inductive FieldOp where | add | mul
deriving DecidableEq, Repr

instance : Inhabited M31 := ⟨RiscvRefinement.M31.zero⟩

def fieldEval (op : FieldOp) (args : List M31) : M31 :=
  let a := args.getD 0 0
  let b := args.getD 1 0
  match op with
  | .add => a + b
  | .mul => a * b

inductive WordOp where
  | add | xor | and | not
  | rotr (amount : Nat)
  | shr (amount : Nat)
deriving DecidableEq, Repr

def wordEval (op : WordOp) (args : List Words.Word) : Words.Word :=
  let a := args.getD 0 0
  let b := args.getD 1 0
  match op with
  | .add => a + b
  | .xor => a ^^^ b
  | .and => a &&& b
  | .not => ~~~a
  | .rotr n => Words.rotr a n
  | .shr n => a >>> n

abbrev FieldBuild := Build M31 FieldOp
abbrev WordBuild := Build Words.Word WordOp

end S31.Graph
