import S31.Semantics.Node

namespace S31

abbrev RawValues := List (String × List Nat)

structure Assignment where
  publicInputs : RawValues
  privateInputs : RawValues := []
  publicOutputs : RawValues
deriving DecidableEq, Repr

def exactFields (raw : RawValues) (names : List String) : Bool :=
  raw.length == names.length && names.all (fun n => (lookup raw n).isSome) &&
    (raw.map Prod.fst).eraseDups.length == raw.length

def assigned (raw : RawValues) (name : String) (shape : Shape) : Result Value := do
  let words ← need (lookup raw name) .invalidValue
  let value ← need (Value.ofNats shape.kind words) .invalidValue
  require (value.shape == shape) .invalidShape
  return value

def Program.claimedWords (p : Program) (a : Assignment) : Result (List M31) := do
  let shapes ← p.validate
  let inputs := p.inputs.filter (fun i => i.visibility == .public)
  require (exactFields a.publicInputs (inputs.map (·.name)) && exactFields a.publicOutputs p.outputs)
    .publicMismatch
  let inputWords ← inputs.mapM (fun i => do
    return (← assigned a.publicInputs i.name i.shape).words)
  let outputWords ← p.outputs.mapM (fun name => do
    return (← assigned a.publicOutputs name (← need (lookup shapes name) .unknownOperand)).words)
  let words := inputWords.flatten ++ outputWords.flatten
  return words ++ List.replicate (8 - words.length) 0

def Program.environment (p : Program) (a : Assignment) : Result Env := do
  let _ ← p.validate
  let privateNames := (p.inputs.filter (fun i => i.visibility == .private)).map (·.name)
  require (exactFields a.privateInputs privateNames) .invalidValue
  let inputs ← p.inputs.mapM (fun i => do
    let raw := if i.visibility == .public then a.publicInputs else a.privateInputs
    return (i.name, ← assigned raw i.name i.shape))
  let values ← p.nodes.foldlM (fun env n => do
    return env ++ [(n.name, ← evaluateNode env n)]) inputs
  for (lhs, rhs) in p.assertions do
    let x ← need (lookup values lhs) .unknownOperand
    let y ← need (lookup values rhs) .unknownOperand
    require (x == y) .assertionFailed
  return values

def Program.evaluate (p : Program) (a : Assignment) : Result (List M31) := do
  let values ← p.environment a
  let claimed ← p.claimedWords a
  for name in p.outputs do
    let actual ← need (lookup values name) .unknownOperand
    let expected ← assigned a.publicOutputs name actual.shape
    require (actual == expected) .publicMismatch
  return claimed

end S31
