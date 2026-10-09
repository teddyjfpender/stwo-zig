import S31.Semantics.Op
import RiscvRefinement.Field.M31

namespace S31

abbrev M31 := RiscvRefinement.M31
abbrev modulus := RiscvRefinement.M31.modulus

inductive Kind where | u16 | m31
deriving DecidableEq, Repr, BEq

inductive Visibility where | «public» | «private»
deriving DecidableEq, Repr, BEq

inductive ProofMode where | transparent | blinded
deriving DecidableEq, Repr, BEq

structure Shape where
  kind : Kind
  length : Nat
deriving DecidableEq, Repr, BEq

structure Value where
  kind : Kind
  words : List M31
deriving DecidableEq, Repr, BEq

def Value.shape (v : Value) : Shape := ⟨v.kind, v.words.length⟩

def Value.valid (v : Value) : Bool :=
  match v.kind with
  | .m31 => true
  | .u16 => v.words.all (fun x => x.val < 65536)

def Value.nats (v : Value) : List Nat := v.words.map (·.val)

def Value.ofNats (kind : Kind) (words : List Nat) : Option Value := do
  let canonical ← words.mapM RiscvRefinement.M31.ofNat?
  let v : Value := ⟨kind, canonical⟩
  if v.valid then some v else none

structure IntegerSpec where
  width : Nat
  signed : Bool
deriving DecidableEq, Repr

def IntegerSpec.decode (encoded : Nat) : Option IntegerSpec :=
  let width := encoded % 256
  if ([8, 16, 32, 64, 128] : List Nat).contains width &&
      (encoded == width || encoded == width + 256) then
    some ⟨width, encoded ≥ 256⟩
  else none

def IntegerSpec.limbs (s : IntegerSpec) : Nat := max 1 (s.width / 16)
def IntegerSpec.limit (s : IntegerSpec) : Nat := 2 ^ s.width

structure Input where
  name : String
  shape : Shape
  visibility : Visibility
deriving DecidableEq, Repr

inductive Step where
  | square
  | add_const (constant : M31)
  | mul_const (constant : M31)
  | mix4
deriving DecidableEq, Repr

structure Node where
  name : String
  op : Op
  lhs : Option String := none
  rhs : Option String := none
  selector : Option String := none
  index : Option Nat := none
  constant : Option Nat := none
  length : Option Nat := none
  rounds : Option Nat := none
  body : Option (List Step) := none
deriving DecidableEq, Repr

structure Program where
  version : Nat := 1
  name : String
  proofMode : ProofMode := .transparent
  inputs : List Input
  nodes : List Node
  assertions : List (String × String)
  outputs : List String
deriving DecidableEq, Repr

abbrev Env := List (String × Value)
abbrev Shapes := List (String × Shape)

def lookup {α : Type} (env : List (String × α)) (name : String) : Option α :=
  (env.find? (fun pair => pair.1 == name)).map Prod.snd

def validName (s : String) : Bool :=
  !s.isEmpty && s.length ≤ 128 &&
    s.toList.all (fun c => c.toNat < 128 && (c.isAlphanum || c == '_'))

inductive Error where
  | malformed | unknownOperand | invalidShape | invalidValue
  | overflow | divisionByZero | assertionFailed | publicMismatch
deriving DecidableEq, Repr

abbrev Result := Except Error

def require (b : Bool) (err : Error := .malformed) : Result Unit :=
  if b then .ok () else .error err

def need {α : Type} (v : Option α) (err : Error := .malformed) : Result α :=
  match v with
  | some x => .ok x
  | none => .error err

end S31
