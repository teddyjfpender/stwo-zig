/-
Differential check of the circuit-AIR composition DAG.

Reads `harness/airvectors.json` (written by `harness/airdump.zig`): each
vector's `expected` value is the real Zig `computeCompositionPolynomial`
(the 11-component circuit table over `builder.Context(QM31)`, eager
values) on `inputs`, and `valid` is the builder's `isCircuitValid` (the
`eq` gates hold). The Lean side must reproduce both from
`CircuitAir.composition` / `CircuitAir.eqConditionsHold`.

Run: `lake exe aircheck harness/airvectors.json`
-/
import StwoVerifier.CircuitAirEval
import Lean.Data.Json

open StwoVerifier
open Lean (Json)

private def jNat (j : Json) : Nat :=
  match j.getNat? with | .ok n => n | .error _ => 0

private def jArr (j : Json) : Array Json :=
  match j.getArr? with | .ok a => a | .error _ => #[]

private def jField (j : Json) (k : String) : Json :=
  match j.getObjVal? k with | .ok v => v | .error _ => Json.null

private def jBool (j : Json) : Bool :=
  match j.getBool? with | .ok b => b | .error _ => false

private def parseQM31 (j : Json) : QM31 :=
  let limbs := (jArr j).map jNat
  QM31.fromM31s (limbs.getD 0 0 : Nat) (limbs.getD 1 0 : Nat)
    (limbs.getD 2 0 : Nat) (limbs.getD 3 0 : Nat)

def main (args : List String) : IO UInt32 := do
  let path := args.headD "harness/airvectors.json"
  let text ← IO.FS.readFile path
  let json ← match Json.parse text with
    | .ok j => pure j
    | .error e => throw (IO.userError s!"parse error: {e}")
  let mut disagree := 0
  let mut index := 0
  for v in jArr (jField json "vectors") do
    let inputs := (jArr (jField v "inputs")).map parseQM31
    let logTrace := jNat (jField v "logTrace")
    let expected := parseQM31 (jField v "expected")
    let expValid := jBool (jField v "valid")
    let got := CircuitAir.composition inputs logTrace
    let gotValid := CircuitAir.eqConditionsHold inputs
    let okVal := QM31.eql got expected
    let okValid := gotValid == expValid
    if okVal ∧ okValid then
      IO.println s!"vector {index}: agree (valid={expValid})"
    else
      IO.println s!"vector {index}: DISAGREE (value {okVal}, valid lean={gotValid} zig={expValid})"
      disagree := disagree + 1
    index := index + 1
  return if disagree = 0 then 0 else 1
