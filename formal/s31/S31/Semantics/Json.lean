import S31.Semantics.Program
import Lean.Data.Json

/-! A strict schema adapter for the normalized JSON data model. The theorem
boundary is the typed `Program`, not Lean's or Zig's raw JSON parser. -/
namespace S31.Json
open Lean

abbrev Parse := Except String

def objectFields (json : Lean.Json) (allowed : List String) : Parse Unit := do
  let object ← json.getObj?
  for (key, _) in object.toList do
    if !allowed.contains key then throw s!"unknown field: {key}"

def field (json : Lean.Json) (key : String) : Parse Lean.Json := json.getObjVal? key
def string (json : Lean.Json) : Parse String := json.getStr?
def nat (json : Lean.Json) : Parse Nat := json.getNat?
def u32 (json : Lean.Json) : Parse Nat := do
  let n ← nat json
  if n < 2^32 then return n else throw "u32 out of range"

def array (parse : Lean.Json → Parse α) (json : Lean.Json) : Parse (List α) := do
  (← json.getArr?).toList.mapM parse

def optional (parse : Lean.Json → Parse α) (json : Lean.Json) (key : String) : Parse (Option α) :=
  match json.getObjVal? key with
  | .error _ => .ok none
  | .ok .null => .ok none
  | .ok value => (parse value).map some

def kind (json : Lean.Json) : Parse Kind := do
  match ← string json with
  | "u16" => return .u16
  | "m31" => return .m31
  | _ => throw "unknown kind"

def visibility (json : Lean.Json) : Parse Visibility := do
  match ← string json with
  | "public" => return .public
  | "private" => return .private
  | _ => throw "unknown visibility"

def proofMode (json : Lean.Json) : Parse ProofMode := do
  match ← string json with
  | "transparent" => return .transparent
  | "blinded" => return .blinded
  | _ => throw "unknown proof mode"

def input (json : Lean.Json) : Parse Input := do
  objectFields json ["name", "kind", "length", "visibility"]
  return ⟨← string (← field json "name"),
    ⟨← kind (← field json "kind"), ← u32 (← field json "length")⟩,
    ← visibility (← field json "visibility")⟩

def step (json : Lean.Json) : Parse Step := do
  objectFields json ["op", "constant"]
  let op ← string (← field json "op")
  let c ← optional u32 json "constant"
  match op, c with
  | "square", none => return .square
  | "mix4", none => return .mix4
  | "add_const", some c | "mul_const", some c =>
    match RiscvRefinement.M31.ofNat? c with
    | none => throw "noncanonical step constant"
    | some c => return if op == "add_const" then .add_const c else .mul_const c
  | _, _ => throw "invalid step"

def node (json : Lean.Json) : Parse Node := do
  objectFields json ["name", "op", "lhs", "rhs", "selector", "index", "constant", "length", "rounds", "body"]
  let opName ← string (← field json "op")
  let op ← match Op.ofWireName opName with
    | some op => pure op
    | none => throw s!"unknown operation: {opName}"
  return {
    name := ← string (← field json "name"), op := op,
    lhs := ← optional string json "lhs", rhs := ← optional string json "rhs",
    selector := ← optional string json "selector", index := ← optional u32 json "index",
    constant := ← optional u32 json "constant", length := ← optional u32 json "length",
    rounds := ← optional u32 json "rounds", body := ← optional (array step) json "body" }

def assertion (json : Lean.Json) : Parse (String × String) := do
  objectFields json ["lhs", "rhs"]
  return (← string (← field json "lhs"), ← string (← field json "rhs"))

def program (json : Lean.Json) : Parse Program := do
  objectFields json ["version", "name", "proof_mode", "inputs", "nodes", "assertions", "public_outputs"]
  let mode ← match json.getObjVal? "proof_mode" with
    | .error _ => pure .transparent
    | .ok value => proofMode value
  return {
    version := ← u32 (← field json "version"), name := ← string (← field json "name"),
    proofMode := mode, inputs := ← array input (← field json "inputs"),
    nodes := ← array node (← field json "nodes"),
    assertions := ← array assertion (← field json "assertions"),
    outputs := ← array string (← field json "public_outputs") }

def values (json : Lean.Json) : Parse RawValues := do
  let object ← json.getObj?
  object.toList.mapM (fun (name, words) => do return (name, ← array nat words))

def assignment (json : Lean.Json) : Parse Assignment := do
  objectFields json ["public_inputs", "private_inputs", "public_outputs"]
  return {
    publicInputs := ← values (← field json "public_inputs"),
    privateInputs := (← optional values json "private_inputs").getD [],
    publicOutputs := ← values (← field json "public_outputs") }

def evaluate (programJson assignmentJson : Lean.Json) : Parse (List Nat) := do
  let p ← program programJson
  let a ← assignment assignmentJson
  match p.evaluate a with
  | .ok words => return words.map (·.val)
  | .error error => throw s!"{repr error}"

end S31.Json
